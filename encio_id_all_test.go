package encio

import (
	"reflect"
	"testing"
)

func Test_idOverrideFn(t *testing.T) {
	type args struct {
		id string
	}
	tests := []struct {
		name    string
		args    args
		wantKey string
		wantErr bool
	}{
		{
			"empty id",
			args{""},
			"",
			true,
		},
		{
			"non-empty id",
			args{"test"},
			"dd1b2ba4c03cc5394107fc0c62f52a47c39854ec841909f53e4a08023eec79d0",
			false,
		},
		{
			"other non-empty id",
			args{"test2"},
			"e5c6faef8bdd598f087e08507a2838914107081f4883d8c61d9a5df672e6a711",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := idOverrideFn(tt.args.id)
			got, err := fn(appID)
			if (err != nil) != tt.wantErr {
				t.Errorf("idOverrideFn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.wantKey) {
				t.Errorf("idOverrideFn() = %v, wantKey %v", got, tt.wantKey)
			}
		})
	}
}
