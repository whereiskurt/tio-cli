package tio

import (
	"sync"
)

type Statistics struct {
	statsMap    map[string]interface{}
	countersMap map[string]int
	ThreadSafe  *sync.Mutex
}

func NewStatistics() *Statistics {
	s := new(Statistics)
	s.ThreadSafe = new(sync.Mutex)
	s.statsMap = make(map[string]interface{})
	s.countersMap = make(map[string]int)

	return s
}

func (stats Statistics) Count(key string) {
	stats.ThreadSafe.Lock()
	stats.countersMap[key]++ //Not thread safe :-)
	stats.ThreadSafe.Unlock()
}

func (stats Statistics) GetCounts() map[string]int {
	stats.ThreadSafe.Lock()
	counts := stats.countersMap //Make a copy.
	stats.ThreadSafe.Unlock()
	return counts
}
