package tenable

import (
  "fmt"
  "encoding/json"
)

func (plugin * Plugin) Pretty(portal *Portal) {
    var pluginDetail Plugin = portal.GetPlugin(string(plugin.Id))
    //Pretty Print the JSON for the Plugin, without attributes.
    x := pluginDetail
    x.Attributes = nil
    ppJSON, _ := json.MarshalIndent(x, "", "  ")
    fmt.Println("")
    fmt.Println("")
    fmt.Printf("----------------------------------\n")
    fmt.Println("Plugin JSON Details")
    fmt.Printf("----------------------------------\n")
    fmt.Println(string(ppJSON))
    fmt.Printf("----------------------------------\n")
    fmt.Println("")
}

func PrettyPlugin(portal *Portal, pluginId string) {
    var pluginDetail Plugin = portal.GetPlugin(pluginId)
    //Pretty Print the JSON for the Plugin, without attributes.
    pluginDetail.Pretty(portal)
}