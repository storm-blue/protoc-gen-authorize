package match

import (
	"reflect"
	"testing"
)

func TestGetPermissions(t *testing.T) {
	tests := []struct {
		name    string
		user    interface{}
		want    []string
		wantErr bool
	}{
		{
			name: "TEST",
			user: struct {
			}{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "TEST",
			user: struct {
				Permissions []string
			}{
				Permissions: []string{"a", "b"},
			},
			want:    []string{"a", "b"},
			wantErr: false,
		},
		{
			name: "TEST",
			user: map[string][]string{
				"Permissions": {"a", "b"},
			},
			want:    []string{"a", "b"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPermissions(tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPermissions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPermissions() got = %v, want %v", got, tt.want)
			}
		})
	}
}
