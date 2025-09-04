package idpclient

import (
	"testing"
)

func TestSanitizeGroupName(t *testing.T) {
	tests := []struct {
		name  string
		group Group
		want  Group
	}{
		{
			name:  "Group name without prefix",
			group: Group{Name: "exampleGroup"},
			want:  Group{Name: "S - exampleGroup"},
		},
		{
			name:  "Group name with prefix",
			group: Group{Name: "S - exampleGroup"},
			want:  Group{Name: "S - exampleGroup"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idpClient := &IDPClient{}
			idpClient.sanitizeGroupName(&tt.group)
			if tt.group.Name != tt.want.Name {
				t.Errorf("sanitizeGroupName() = %v, want %v", tt.group.Name, tt.want.Name)
			}
		})
	}
}
