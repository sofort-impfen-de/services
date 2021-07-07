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

	for _, notification := range params.Notifications {
		mail, err := c.decryptMail(notification, notificationsPrivateKey)
		if err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}

		mailOnBlockList, err := c.mailOnBlockList(hex.EncodeToString(crypto.Hash(mail)))
		if !mailOnBlockList {
			sendMail(string(mail), c.settings.Mail)
		}

	}
	return context.Acknowledge()
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

	mailAlreadyOnyBlockList, err := c.mailOnBlockList(params.Data)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !mailAlreadyOnyBlockList {
		err = c.addRemovedMail(params.Data)
		if err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	return context.Acknowledge()
}

func (c *Notification) getRemovedMailsSet() services.Set {
	return c.db.Set("removedMails", []byte("mails"))
}

func (c *Notification) addRemovedMail(mailHashToRemove string) error {
	removedMails := c.getRemovedMailsSet()
	encrypt, err := crypto.Encrypt([]byte(mailHashToRemove), c.settings.Secret)
	if err != nil {
		return err
	}

	marshal, err := json.Marshal(encrypt)
	if err != nil {
		return err
	}

	err = removedMails.Add(marshal)
	if err != nil {
		return err
	}

	return nil
}

func (c *Notification) mailOnBlockList(mailHashToCheck string) (bool, error) {
	removedMails := c.getRemovedMailsSet()

	removedMailMembers, err := removedMails.Members()
	if err != nil {
		return false, err
	}

	for _, member := range removedMailMembers {
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

func sendMail(mail string, mailSettings *services.MailSettings) {
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
		services.Log.Error(err)
	}
}
