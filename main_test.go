package main

import (
	"testing"
	"time"
)

func Test_device_isActive(t *testing.T) {
	type fields struct {
		timeSinceLastSeen time.Duration
	}
	tests := []struct {
		name              string
		timeSinceLastSeen time.Duration
		want              bool
	}{
		{name: "active", timeSinceLastSeen: time.Duration(0), want: true},
		{name: "inactive", timeSinceLastSeen: time.Duration(10), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &device{
				timeSinceLastSeen: tt.timeSinceLastSeen,
			}
			if got := d.isActive(); got != tt.want {
				t.Errorf("device.isActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_truncateString(t *testing.T) {
	type args struct {
		str string
		num int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"too short for concatenation", args{"s", 10}, "s"},
		{"example 1", args{"hello", 2}, "he..."},
		{"example 1", args{"hello there", 8}, "hello..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateString(tt.args.str, tt.args.num); got != tt.want {
				t.Errorf("truncateString() = %v, want %v", got, tt.want)
			}
		})
	}
}
