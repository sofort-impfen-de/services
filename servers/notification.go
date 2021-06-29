package servers

import (
	"github.com/kiebitz-oss/services"
	"github.com/kiebitz-oss/services/jsonrpc"
	"github.com/kiprotect/go-helpers/forms"
)

type Notification struct {
	settings *services.NotificationSettings
	server   *jsonrpc.JSONRPCServer
}

func (c *Notification) Start() error {
	return c.server.Start()
}

func (c *Notification) Stop() error {
	return c.server.Stop()
}

type sendNotificationParams struct {
}

var SendNotificationsForm = forms.Form{
	Fields: []forms.Field{},
}

func MakeNotification(settings *services.Settings) (*Notification, error) {

	Notification := &Notification{
		settings: settings.Notification,
	}

	methods := map[string]*jsonrpc.Method{
		"sendNotifications": {
			Form:    &SendNotificationsForm,
			Handler: Notification.sendNotifications,
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

	return context.Acknowledge()
}
