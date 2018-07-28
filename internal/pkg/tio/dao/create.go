package dao

import (
	"fmt"
)

//https://cloud.tenable.com/tags/assets/assignments
//{"action":"add","assets":"b1058b41-378d-4bbd-8dfc-e90344cf6070","tags":[{"category_name":"addenda-agents","value":"testtagkph","valueId":"4d6983a8-0956-4e04-8cc7-f625bd2dc912"}]}

var tagEndPoint string = "https://cloud.tenable.com/tags/assets/assignments"

func (trans *Translator) TagByAssetUUID(assetUUID string, categoryName string, value string) (err error) {
	tagUUID, err := trans.getTagUUID(categoryName, value)
	if err != nil {
		trans.Errorf("%s", err)
		return err
	}

	postBody := fmt.Sprintf("{\"action\":\"add\",\"assets\":\"%s\",\"tags\":[{\"category_name\":\"%s\",\"value\":\"%s\",\"valueId\":\"%s\"}]}", assetUUID, categoryName, value, tagUUID)
	_, err = trans.PortalCache.PostJSON(tagEndPoint, postBody)
	if err != nil {
		trans.Errorf("%s", err)
	}

	return err
}

func (trans *Translator) UntagByAssetUUID(assetUUID string, categoryName string, value string) (err error) {
	tagUUID, err := trans.getTagUUID(categoryName, value)
	if err != nil {
		trans.Errorf("%s", err)
		return err
	}

	postBody := fmt.Sprintf("{\"action\":\"remove\",\"assets\":\"%s\",\"tags\":[{\"uuid\":\"%s\"}]}", assetUUID, tagUUID)
	_, err = trans.PortalCache.PostJSON(tagEndPoint, postBody)
	if err != nil {
		trans.Errorf("%s", err)
	}

	return err
}

//https://cloud.tenable.com/workbenches/assets?date_range=0&filter.0.quality=set-has&filter.0.filter=tag.addenda-agents&filter.0.value=testtagkph&filter.search_type=and
//https://cloud.tenable.com/workbenches/assets?date_range=30&filter.0.quality=set-has&filter.0.filter=tag.addenda-agents&filter.0.value=testtagkph&filter.search_type=and

//DELETE:
//https://cloud.tenable.com/tags/assets/assignments
//{"action":"remove","assets":"b1058b41-378d-4bbd-8dfc-e90344cf6070","tags":[{"uuid":"4d6983a8-0956-4e04-8cc7-f625bd2dc912"}]}
