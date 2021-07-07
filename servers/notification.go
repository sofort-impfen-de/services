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

type sendNotificationParams struct {
}

type removeMailParams struct {
	Data string `json:"data"`
}

var SendNotificationsForm = forms.Form{
	Fields: []forms.Field{},
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

	sendMails(c.settings.Mail)

	return context.Acknowledge()
}

func (c *Notification) removeMail(context *jsonrpc.Context, params *removeMailParams) *jsonrpc.Response {
	removedMails := c.db.Set("removedMails", []byte("mails"))

	removedMailMembers, err := removedMails.Members()
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	mailAlreadyRemoved, err := c.mailAlreadyRemoved(params.Data, removedMailMembers)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !mailAlreadyRemoved {
		err = c.addRemovedMail(params.Data, removedMails)
		if err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	return context.Acknowledge()
}

func (c *Notification) addRemovedMail(mailHashToRemove string, removedMails services.Set) error {
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

func (c *Notification) mailAlreadyRemoved(mailHashToCheck string, removedMailMembers []*services.SetEntry) (bool, error) {
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

func sendMails(mailSettings *services.MailSettings) {
	// Set up authentication information.
	auth := smtp.PlainAuth("", mailSettings.SmtpUser, mailSettings.SmtpPassword, mailSettings.SmtpHost)

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	to := []string{"recipient@example.net"}
	msg := "From: " + mailSettings.Sender + "\n" +
		"To: recipient@example.net \n" +
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
