// Kiebitz - Privacy-Friendly Appointment Scheduling
// Copyright (C) 2021-2021 The Kiebitz Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package servers

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/kiebitz-oss/services"
	"github.com/kiebitz-oss/services/crypto"
	"github.com/kiebitz-oss/services/jsonrpc"
	"github.com/kiprotect/go-helpers/forms"
	"net/smtp"
	"time"
)

type Notification struct {
	settings *services.NotificationSettings
	server   *jsonrpc.JSONRPCServer
	db       services.Database
}

func (c *Notification) Start() error {
	return c.server.Start()
}

func (c *Notification) Stop() error {
	return c.server.Stop()
}

type MailNotification struct {
	PublicKey []byte `json:"publicKey"`
	Iv        []byte `json:"iv"`
	Data      []byte `json:"data"`
}

type sendNotificationParams struct {
	Notifications []MailNotification `json:"notifications"`
}

type removeMailParams struct {
	Data string `json:"data"`
}

var MailNotificationForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding: "base64",
				},
			},
		},
		{
			Name: "iv",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding: "base64",
				},
			},
		},
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding: "base64",
				},
			},
		},
	},
}

var SendNotificationsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "notifications",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &MailNotificationForm,
						},
					},
				},
			},
		},
	},
}

var RemoveMailForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
	},
}

func MakeNotification(settings *services.Settings) (*Notification, error) {

	Notification := &Notification{
		settings: settings.Notification,
		db:       settings.DatabaseObj,
	}

	methods := map[string]*jsonrpc.Method{
		"sendNotifications": {
			Form:    &SendNotificationsForm,
			Handler: Notification.sendNotifications,
		},
		"removeMail": {
			Form:    &RemoveMailForm,
			Handler: Notification.removeMail,
		},
	}

	handler, err := jsonrpc.MethodsHandler(methods)

	if err != nil {
		return nil, err
	}

	if jsonrpcServer, err := jsonrpc.MakeJSONRPCServer(settings.Notification.RPC, handler); err != nil {
		return nil, err
	} else {
		Notification.server = jsonrpcServer
		return Notification, nil
	}

}

func (c *Notification) sendNotifications(context *jsonrpc.Context, params *sendNotificationParams) *jsonrpc.Response {
	notificationsKey := c.settings.Key("notifications")
	notificationsPrivateKey, err := crypto.LoadPrivateKey(notificationsKey.PrivateKey)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	MailBlockSet := c.getBlockedMailsSet()
	mailBlockSetMembers, err := MailBlockSet.Members()
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	sentMails := c.getSentMailsSet()
	notifiedMails, err := sentMails.RangeByScore(c.getMailingThresholdInSeconds(), time.Now().Unix())
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	c.processNotifications(
		params.Notifications,
		notificationsPrivateKey,
		mailBlockSetMembers,
		notifiedMails,
		sentMails)
	c.recentlyNotifiedHousekeeping()

	return context.Acknowledge()
}

func (c *Notification) processNotifications(notifications []MailNotification,
	notificationsPrivateKey *ecdsa.PrivateKey,
	removedMailMembers []*services.SetEntry,
	notifiedMails []*services.SortedSetEntry,
	sentMails services.SortedSet) {
	for _, notification := range notifications {
		mail, err := c.decryptMail(notification, notificationsPrivateKey)
		if err != nil {
			services.Log.Error(err)
			continue
		}

		hashedMail := c.hashMail(mail)
		mailOnBlockList, err := c.mailOnBlockList(hashedMail, removedMailMembers)
		if err != nil {
			services.Log.Error(err)
			continue
		}

		recentlyNotified, err := c.recentlyNotified(hashedMail, notifiedMails)
		if err != nil {
			services.Log.Error(err)
			continue
		}

		if !mailOnBlockList && !recentlyNotified {
			err := c.performMailNotification(mail, sentMails)
			if err != nil {
				services.Log.Error(err)
				continue
			}
		}

	}
}

func (c *Notification) hashMail(mail []byte) string {
	return hex.EncodeToString(crypto.Hash(mail))
}

func (c *Notification) performMailNotification(mail []byte, sentMails services.SortedSet) error {
	mailAddress := string(mail)
	err := sendMail(mailAddress, c.settings.Mail)
	if err != nil {
		return err
	} else {
		marshal, err := c.encryptAndSerialize(c.hashMail(mail))
		if err != nil {
			return err
		}
		err = sentMails.Add(marshal, time.Now().Unix())
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Notification) decryptMail(notification MailNotification, notificationsPrivateKey *ecdsa.PrivateKey) (mail []byte, err error) {
	requestPublicKey, err := crypto.LoadPublicKey(notification.PublicKey)
	if err != nil {
		return nil, err
	}

	encryptedData := &crypto.EncryptedData{
		Data: notification.Data,
		IV:   notification.Iv,
	}

	sharedKey := crypto.DeriveKey(requestPublicKey, notificationsPrivateKey)
	decrypt, err := crypto.Decrypt(encryptedData, sharedKey)
	if err != nil {
		return nil, err
	}

	return decrypt, nil
}

func (c *Notification) removeMail(context *jsonrpc.Context, params *removeMailParams) *jsonrpc.Response {
	blockedMailsSet := c.getBlockedMailsSet()

	blockedMailsSetMembers, err := blockedMailsSet.Members()
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	mailAlreadyOnyBlockList, err := c.mailOnBlockList(params.Data, blockedMailsSetMembers)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !mailAlreadyOnyBlockList {
		err = c.addBlockedMail(params.Data, blockedMailsSet)
		if err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	return context.Acknowledge()
}

func (c *Notification) getBlockedMailsSet() services.Set {
	return c.db.Set("notifications", []byte("removedMails"))
}

func (c *Notification) getSentMailsSet() services.SortedSet {
	return c.db.SortedSet("notifications", []byte("sentMails"))
}

func (c *Notification) addBlockedMail(mailHashToAdd string, blockedMailsSet services.Set) error {
	marshal, err := c.encryptAndSerialize(mailHashToAdd)
	if err != nil {
		return err
	}

	err = blockedMailsSet.Add(marshal)
	if err != nil {
		return err
	}

	return nil
}

func (c *Notification) encryptAndSerialize(mailHashToAdd string) ([]byte, error) {
	encrypt, err := crypto.Encrypt([]byte(mailHashToAdd), c.settings.Secret)
	if err != nil {
		return nil, err
	}

	marshal, err := json.Marshal(encrypt)
	if err != nil {
		return nil, err
	}
	return marshal, err
}

func (c *Notification) mailOnBlockList(mailHashToCheck string, blockList []*services.SetEntry) (bool, error) {
	for _, member := range blockList {
		var encryptedMailHash *crypto.EncryptedData
		err := json.Unmarshal(member.Data, &encryptedMailHash)
		if err != nil {
			return false, err
		}
		decryptedMailHash, err := crypto.Decrypt(encryptedMailHash, c.settings.Secret)
		if err != nil {
			return false, err
		}

		if string(decryptedMailHash) == mailHashToCheck {
			return true, nil
		}
	}
	return false, nil
}

func (c *Notification) recentlyNotified(mail string, recentlyNotifiedMails []*services.SortedSetEntry) (bool, error) {
	for _, notifiedMail := range recentlyNotifiedMails {
		var encryptedMailHash *crypto.EncryptedData
		err := json.Unmarshal(notifiedMail.Data, &encryptedMailHash)
		if err != nil {
			return false, err
		}
		decryptedMailHash, err := crypto.Decrypt(encryptedMailHash, c.settings.Secret)
		if err != nil {
			return false, err
		}

		if string(decryptedMailHash) == mail {
			return true, nil
		}
	}

	return false, nil
}

func (c *Notification) recentlyNotifiedHousekeeping() {
	err := c.getSentMailsSet().RemoveRangeByScore(0, c.getMailingThresholdInSeconds()-1)
	if err != nil {
		services.Log.Error(err)
	}
}

func (c *Notification) getMailingThresholdInSeconds() int64 {
	delayInSeconds := c.settings.Mail.MailDelay * 60
	return time.Now().Unix() - delayInSeconds
}

func sendMail(mail string, mailSettings *services.MailSettings) error {
	// Set up authentication information.
	auth := smtp.PlainAuth("", mailSettings.SmtpUser, mailSettings.SmtpPassword, mailSettings.SmtpHost)

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	to := []string{"recipient@example.net"}
	msg := "From: " + mailSettings.Sender + "\n" +
		"To: " + mail + " \n" +
		"MIME-version: 1.0;\n" +
		"Content-Type: text/html;charset=\"UTF-8\";\n" +
		"Subject: " + mailSettings.MailSubject + "\n\n" +
		mailSettings.MailTemplate
	err := smtp.SendMail(
		fmt.Sprintf("%s:%d", mailSettings.SmtpHost, mailSettings.SmtpPort),
		auth,
		mailSettings.Sender,
		to,
		[]byte(msg))

	if err != nil {
		return err
	}

	return nil
}
