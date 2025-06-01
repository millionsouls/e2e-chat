package common

import "encoding/json"

func SerializeMessage(msg EncryptedMessage) ([]byte, error) {
	return json.Marshal(msg)
}

func DeserializeMessage(data []byte) (EncryptedMessage, error) {
	var msg EncryptedMessage
	err := json.Unmarshal(data, &msg)
	return msg, err
}
