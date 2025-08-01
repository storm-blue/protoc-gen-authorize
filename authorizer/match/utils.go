package match

import (
	"fmt"
	"reflect"
)

// GetPermissions 安全获取 []string 类型的 Permissions 字段
func GetPermissions(user interface{}) ([]string, error) {
	// 处理 nil 输入
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}

	val := reflect.ValueOf(user)

	// 解引用指针
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return nil, fmt.Errorf("user cannot be nil")
		}
		val = val.Elem()
	}

	// 根据类型处理
	switch val.Kind() {
	case reflect.Struct:
		return getFromStruct(val)
	case reflect.Map:
		return getFromMap(val)
	default:
		return nil, fmt.Errorf("unsupported type: %v", val.Type())
	}
}

// 从结构体获取字段
func getFromStruct(val reflect.Value) ([]string, error) {
	field := val.FieldByName("Permissions")
	if !field.IsValid() {
		return nil, fmt.Errorf("field 'Permissions' not found")
	}
	return convertToStringSlice(field)
}

// 从 map 获取字段
func getFromMap(val reflect.Value) ([]string, error) {
	// 确保 map 键是字符串类型
	if val.Type().Key().Kind() != reflect.String {
		return nil, fmt.Errorf("map key must be string")
	}

	// 查找 Permissions 键
	key := reflect.ValueOf("Permissions")
	field := val.MapIndex(key)
	if !field.IsValid() {
		return nil, fmt.Errorf("field 'Permissions' not found")
	}
	return convertToStringSlice(field)
}

// 转换为 []string 并验证类型
func convertToStringSlice(field reflect.Value) ([]string, error) {
	// 处理指针类型字段
	if field.Kind() == reflect.Ptr {
		if field.IsNil() {
			return nil, fmt.Errorf("field 'Permissions' cannot be nil")
		}
		field = field.Elem()
	}

	// 检查是否为切片
	if field.Kind() != reflect.Slice {
		return nil, fmt.Errorf("field 'Permissions' is not a slice")
	}

	// 检查元素类型是否为 string
	if field.Type().Elem().Kind() != reflect.String {
		return nil, fmt.Errorf("field 'Permissions' elements are not strings")
	}

	// 转换为 []string
	result := make([]string, field.Len())
	for i := 0; i < field.Len(); i++ {
		result[i] = field.Index(i).String()
	}
	return result, nil
}
