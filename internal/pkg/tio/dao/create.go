package dao

import (
	"fmt"
)

func (trans *Translator) CreateTag(assetUUID string, category string, value string) (err error) {
	tagUUID := "lookup"

	postBody := fmt.Sprintf("{\"action\":\"add\",\"assets\":\"%s\",\"tags\":[{\"category_name\":\"%s\",\"value\":\"%s\",\"valueId\":\"%s\"}]}", assetUUID, category, value, tagUUID)

	fmt.Println(postBody)

	return err
}
