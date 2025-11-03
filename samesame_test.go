package samesame

import "testing"

func TestAdd(t *testing.T) {
	tests := []struct {
		name string
		x    int
		y    int
		want int
	}{
		{
			name: "positive numbers",
			x:    2,
			y:    3,
			want: 5,
		},
		{
			name: "negative numbers",
			x:    -2,
			y:    -3,
			want: -5,
		},
		{
			name: "mixed numbers",
			x:    -2,
			y:    3,
			want: 1,
		},
		{
			name: "zeros",
			x:    0,
			y:    0,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Add(tt.x, tt.y); got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.x, tt.y, got, tt.want)
			}
		})
	}
}
