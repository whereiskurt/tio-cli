package dao

import (
	"encoding/json"
	"fmt"

	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
)

func (trans *Translator) CreateTagCategory(categoryName string) (categoryUUID string, err error) {
	var tagEndPoint string = "https://cloud.tenable.com/tags/categories"

	postBody := fmt.Sprintf("{\"name\":\"%s\",\"description\":\"\"}", categoryName)
	raw, err := trans.PortalCache.PostJSON(tagEndPoint, postBody)

	var tag tenable.TagCategory

	err = json.Unmarshal([]byte(string(raw)), &tag)
	if err != nil {
		trans.Warnf("Couldn't unmarshal tenable.TagCategory after POST: %s\n%s", err, raw)
		return categoryUUID, err
	}

	categoryUUID = tag.UUID

	return categoryUUID, err
}
func (trans *Translator) CreateTagValue(categoryUUID string, categoryName string, categoryValue string) (err error) {
	var tagEndPoint string = "https://cloud.tenable.com/tags/values"

	postBody := fmt.Sprintf("{\"category_uuid\":\"%s\",\"category_name\":\"%s\",\"category_description\":\"\",\"value\":\"%s\",\"description\":\"\"}", categoryUUID, categoryName, categoryValue)

	body, err := trans.PortalCache.PostJSON(tagEndPoint, postBody)
	if err != nil {
		trans.Errorf("%s:%s", err, body)
	}

	return err
}


func (trans *Translator) DeleteTagValue(valueUUID string) (err error) {
	tagEndPoint := fmt.Sprintf("https://cloud.tenable.com/tags/values/%s", valueUUID)

	_, err = trans.PortalCache.Delete(tagEndPoint)

	//DELETE:https://cloud.tenable.com/tags/categories/39d2705b-9c06-4c1e-9f03-98c1769705de
	//DELETE:https://cloud.tenable.com/tags/values/25214874-a953-4ef2-851d-f773357ec490

	return err
}

func (trans *Translator) TagByAssetUUID(assetUUID string, categoryName string, value string) (err error) {
	var tagEndPoint string = "https://cloud.tenable.com/tags/assets/assignments"

	tagUUID, err := trans.GetTagUUID(categoryName, value)
	if err != nil {
		trans.Errorf("%s", err)
		return err
	}

	postBody := fmt.Sprintf("{\"action\":\"add\",\"assets\":\"%s\",\"tags\":[{\"category_name\":\"%s\",\"value\":\"%s\",\"valueId\":\"%s\"}]}", assetUUID, categoryName, value, tagUUID)
	body, err := trans.PortalCache.PostJSON(tagEndPoint, postBody)
	if err != nil {
		trans.Errorf("%s:%s", err, body)
	}

	//TODO: InvalidateAssetCache
	return err
}

func (trans *Translator) UntagByAssetUUID(assetUUID string, categoryName string, value string) (err error) {
	var tagEndPoint string = "https://cloud.tenable.com/tags/assets/assignments"

	tagUUID, err := trans.GetTagUUID(categoryName, value)
	if err != nil {
		trans.Errorf("%s", err)
		return err
	}

	postBody := fmt.Sprintf("{\"action\":\"remove\",\"assets\":\"%s\",\"tags\":[{\"uuid\":\"%s\"}]}", assetUUID, tagUUID)
	_, err = trans.PortalCache.PostJSON(tagEndPoint, postBody)
	if err != nil {
		trans.Errorf("%s", err)
	}

	//TODO: InvalidateAssetCache
	return err
}

//https://cloud.tenable.com/workbenches/assets?date_range=0&filter.0.quality=set-has&filter.0.filter=tag.addenda-agents&filter.0.value=testtagkph&filter.search_type=and
//https://cloud.tenable.com/workbenches/assets?date_range=30&filter.0.quality=set-has&filter.0.filter=tag.addenda-agents&filter.0.value=testtagkph&filter.search_type=and

//DELETE:
//https://cloud.tenable.com/tags/assets/assignments
//{"action":"remove","assets":"b1058b41-378d-4bbd-8dfc-e90344cf6070","tags":[{"uuid":"4d6983a8-0956-4e04-8cc7-f625bd2dc912"}]}
