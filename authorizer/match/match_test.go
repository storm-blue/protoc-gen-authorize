package match

import (
	"github.com/autom8ter/proto/gen/authorize"
	"reflect"
	"testing"
)

func Test_getExpressions(t *testing.T) {
	tests := []struct {
		name  string
		rules *authorize.RuleSet
		want  []string
	}{
		{
			name: "TEST",
			rules: &authorize.RuleSet{
				Rules: []*authorize.Rule{
					{
						Expression: "abc:${asd.zzx}:asdqe",
					},
					{
						Expression: "abc:${asd.zzx}:asdqe${abc.aaa}",
					},
				},
			},
			want: []string{"abc:${asd.zzx}:asdqe", "abc:${asd.zzx}:asdqe${abc.aaa}"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getExpressions(tt.rules); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getExpressions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getNeedPermissions(t *testing.T) {
	tests := []struct {
		name        string
		expressions []string
		data        map[string]interface{}
		want        []string
		wantErr     bool
	}{
		{
			name:        "TEST",
			expressions: []string{"app:{{.request.Namespace}}/{{.request.Name}}.add", "app:{{.user.Namespace}}/{{.user.Name}}:get"},
			data: map[string]interface{}{
				"request": map[string]interface{}{
					"Namespace": "test",
					"Name":      "app1",
				},
				"user": map[string]interface{}{
					"Namespace": "dev",
					"Name":      "tom",
				},
			},
			want:    []string{"app:test/app1.add", "app:dev/tom:get"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getNeedPermissions(tt.expressions, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("getNeedPermissions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getNeedPermissions() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_permissionMatch(t *testing.T) {
	tests := []struct {
		name           string
		needPermission string
		permission     string
		want           bool
		wantErr        bool
	}{
		{
			name:           "TEST",
			needPermission: "app:shop/dev:add",
			permission:     "*:*:*",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "app:shop.c/dev:add",
			permission:     "*:shop.c/*:*",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "app:shop.c/dev:add",
			permission:     "*:shop.b/*:*",
			want:           false,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "ingress:www.shop.com/dev:add",
			permission:     "*:.*/*:*",
			want:           false,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "ingress:www.shop.com/dev:add",
			permission:     "*:*.*/*:*",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "ingress:www.shop.com/dev:add",
			permission:     "*:*.*/*:get",
			want:           false,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "ingress:*:add",
			permission:     "*:*.*/*:add",
			want:           false,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "ingress::add",
			permission:     "*:*.*/*:add",
			want:           false,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "ingress::add",
			permission:     "*:*:add",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "ingress::::add",
			permission:     "*:*:add",
			want:           false,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "ingress:qa1-api.xinfei.cn:add",
			permission:     "*:*:add",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "*:qa1-api.xinfei.cn:add",
			permission:     "*:*:add",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "**:qa1-api.xinfei.cn:add",
			permission:     "*:*:add",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "*/a:qa1-api.xinfei.cn:add",
			permission:     "*/a:*:add",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "*/a:qa1-api.xinfei.cn:add",
			permission:     "*:*:add",
			want:           true,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "*/a:qa1-api.xinfei.cn:add",
			permission:     "a/*:*:add",
			want:           false,
			wantErr:        false,
		},
		{
			name:           "TEST",
			needPermission: "*/a:qa1-api.xinfei.我擦嘞:add",
			permission:     "*:*:add",
			want:           true,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := permissionMatch(tt.needPermission, tt.permission)
			if (err != nil) != tt.wantErr {
				t.Errorf("permissionMatch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("permissionMatch() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rendTemplate(t *testing.T) {
	tests := []struct {
		name    string
		t1      string
		data    map[string]interface{}
		want    string
		wantErr bool
	}{
		{
			name: "TEST",
			t1:   "abc{{.aaa.bbb.ccc}}",
			data: map[string]interface{}{
				"aaa": map[string]interface{}{
					"bbb": map[string]interface{}{
						"ccc": "ddd",
					},
				},
			},
			want:    "abcddd",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rendNeedPermission(tt.t1, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("rendNeedPermission() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("rendNeedPermission() got = %v, want %v", got, tt.want)
			}
		})
	}
}
