package analysis

import "testing"

func TestCandidateScoreThreshold(t *testing.T) {
	tests := []struct {
		name           string
		blockThreshold int
		want           int32
	}{
		{
			name:           "uses floor when configured threshold is higher",
			blockThreshold: 60,
			want:           30,
		},
		{
			name:           "keeps lower configured threshold",
			blockThreshold: 25,
			want:           25,
		},
		{
			name:           "defaults to floor when threshold is unset",
			blockThreshold: 0,
			want:           30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := &BlockManager{
				config: BlockManagerConfig{
					BlockThreshold: tt.blockThreshold,
				},
			}

			if got := bm.candidateScoreThreshold(); got != tt.want {
				t.Fatalf("candidateScoreThreshold() = %d, want %d", got, tt.want)
			}
		})
	}
}
