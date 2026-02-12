package scanner

type EventType int

const (
	EventURLTrying EventType = iota

	EventResultFound

	EventScanComplete
)

type ScanEvent struct {
	Type   EventType
	URL    string
	Result *Result
}
