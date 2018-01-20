package tio

import (
	"sync"
)

type StatType string

type Statistics struct {
	ThreadSafe  *sync.Mutex
	statsMap    map[StatType]interface{}
	countersMap map[StatType]int
}

func NewStatistics() *Statistics {
	s := new(Statistics)
	s.ThreadSafe = new(sync.Mutex)
	s.statsMap = make(map[StatType]interface{})
	s.countersMap = make(map[StatType]int)

	return s
}

func (stats Statistics) Tick(key StatType) {
}
func (stats Statistics) Tock(key StatType) {
}

func (stats Statistics) Count(key StatType) {
	stats.ThreadSafe.Lock()
	stats.countersMap[key]++ //Not thread safe :-)
	stats.ThreadSafe.Unlock()
}

func (stats Statistics) GetCounts() map[StatType]int {
	stats.ThreadSafe.Lock()
	counts := stats.countersMap //Make a copy.
	stats.ThreadSafe.Unlock()
	return counts
}
