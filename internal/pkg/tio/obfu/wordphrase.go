package util

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"strings"
	//"time"
)

//var src = rand.NewSource(time.Now().UnixNano())
var src = rand.NewSource(1)
var r *rand.Rand = rand.New(src)

var aoff = 0
var woff = 0
var fqdnoff = 0

var animalP []int = nil
var namesP []int = nil
var animals []string = nil
var names []string = nil

func init() {
	rawanimal, _ := ioutil.ReadFile("configs/wordlist/animalnames.txt")
	animals = strings.Split(string(rawanimal), "\n")

	rawnames, _ := ioutil.ReadFile("configs/wordlist/1000englishwords.txt")
	names = strings.Split(string(rawnames), "\n")

	animalP = r.Perm(len(animals))
	namesP = r.Perm(len(names))

	return
}

func Animal() string {
	aoff = aoff + 1
	animal := animals[animalP[aoff%len(animalP)]]
	return animal
}

func Word() (word string)  {
	woff = woff + 1
	word = names[namesP[woff%len(namesP)]]
	return word
}

func Hostname(fqdn string) (hostname string) {
	fqdnoff = fqdnoff + 1
	hostnum := fqdnoff / len(animals)

	animal := Animal()
	animal = strings.Replace(animal, ",", "", -1)
	animal = strings.Replace(animal, ".", "", -1)

	hostname = strings.ToLower(fmt.Sprintf("%s%02d.%s", Animal(), hostnum, fqdn))

	return hostname
}

func PopularEnglishAnimalPhrase() string {
	randAnimalPhrase := fmt.Sprintf("%v %v %v %v", Animal(), Animal(), strings.Title(Word()), Animal())
	return randAnimalPhrase
}

func FakeIpv4() string {
	size := 4
	ip := make([]byte, size)
	for i := 0; i < size; i++ {
		ip[i] = byte(r.Intn(256))
	}
	return net.IP(ip).To4().String()
}

func FakePrivateIpv4(prefix []byte) string {
	size := 4
	ip := make([]byte, size)
	for i := 0; i < size; i++ {
		ip[i] = byte(r.Intn(256))
	}

	if len(prefix) < 3 {
		for i, _ := range prefix {
			ip[i] = prefix[i]
		}
	}

	return net.IP(ip).To4().String()
}
