package mirroring

import "github.com/sigstore/rekor/pkg/generated/models"

func (h *LogHandler) IsSTHUpdated() (bool, error) {
	sth := h.metadata.LogInfo.SignedTreeHead.Signature

	remoteSig, err := h.GetRemoteRootSignature()
	if err != nil {
		return false, err
	}

	if sth.String() != remoteSig.String() {
		return true, nil
	} else {
		return false, nil
	}

}

func (h *LogHandler) FetchLeavesByRange(firstSize, lastSize int64) ([]models.LogEntry, error) {
	return nil, nil
}
