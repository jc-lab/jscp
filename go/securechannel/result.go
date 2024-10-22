package securechannel

import (
	"fmt"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/pkg/errors"
)

func receiveResultAddAlert(result *Transfer, alert *payloadpb.Alert) *Transfer {
	result.Send = append(result.Send, &payloadpb.Payload{
		Message: &payloadpb.Payload_UnencryptedAlert{
			UnencryptedAlert: alert,
		},
	})
	result.Error = errors.WithStack(fmt.Errorf("alert: %+v", alert))
	result.Finish = true
	return result
}

func receiveResultSetError(result *Transfer, err error) *Transfer {
	result.Send = append(result.Send, &payloadpb.Payload{
		Message: &payloadpb.Payload_UnencryptedAlert{
			UnencryptedAlert: &payloadpb.Alert{
				Code: payloadpb.AlertCode_AlertOther,
			},
		},
	})
	result.Error = err
	result.Finish = true
	return result
}
