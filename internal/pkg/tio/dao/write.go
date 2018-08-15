package dao

import (
	"encoding/json"
	"fmt"

	"github.com/whereiskurt/tio-cli/internal/pkg/tio/api/tenable"
)

func (trans *Translator) CreateTagCategory(categoryName string) (categoryUUID string, err error) {
	var url string = "https://cloud.tenable.com/tags/categories"

	postBody := fmt.Sprintf("{\"name\":\"%s\",\"description\":\"\"}", categoryName)
	raw, err := trans.PortalCache.PostJSON(url, postBody)

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
	var url string = "https://cloud.tenable.com/tags/values"

	postBody := fmt.Sprintf("{\"category_uuid\":\"%s\",\"category_name\":\"%s\",\"category_description\":\"\",\"value\":\"%s\",\"description\":\"\"}", categoryUUID, categoryName, categoryValue)

	body, err := trans.PortalCache.PostJSON(url, postBody)
	if err != nil {
		trans.Errorf("ERROR: %s\n%s", err, body)
	}

	return err
}

func (trans *Translator) DeleteTagValue(valueUUID string) (err error) {
	var url string = fmt.Sprintf("https://cloud.tenable.com/tags/values/%s", valueUUID)

	trans.Infof(fmt.Sprintf("Calling DELETE on TagValue UUID: %s", valueUUID))

	_, err = trans.PortalCache.Delete(url)

	return err
}

func (trans *Translator) TagByAssetUUID(assetUUID string, categoryName string, value string) (err error) {
	var url string = "https://cloud.tenable.com/tags/assets/assignments"

	tagUUID, err := trans.GetTagUUID(categoryName, value)
	if err != nil {
		trans.Errorf("%s", err)
		return err
	}

	data := fmt.Sprintf("{\"action\":\"add\",\"assets\":\"%s\",\"tags\":[{\"category_name\":\"%s\",\"value\":\"%s\",\"valueId\":\"%s\"}]}", assetUUID, categoryName, value, tagUUID)
	body, err := trans.PortalCache.PostJSON(url, data)
	if err != nil {
		trans.Errorf("%s:%s", err, body)
	}

	//TODO: InvalidateAssetCache
	return err
}

func (trans *Translator) UntagByAssetUUID(assetUUID string, categoryName string, value string) (err error) {
	var url string = "https://cloud.tenable.com/tags/assets/assignments"

	tagUUID, err := trans.GetTagUUID(categoryName, value)
	if err != nil {
		trans.Errorf("%s", err)
		return err
	}

	data := fmt.Sprintf("{\"action\":\"remove\",\"assets\":\"%s\",\"tags\":[{\"uuid\":\"%s\"}]}", assetUUID, tagUUID)
	_, err = trans.PortalCache.PostJSON(url, data)
	if err != nil {
		trans.Errorf("%s", err)
	}

	//TODO: InvalidateAssetCache
	return err
}
