package classifier

import "iscan/internal/model"

type ConfidenceSignals struct {
	Base                model.Confidence
	EvidenceCount       int
	ResolverCount       int
	ControlCorroborated bool
	CrossLayerAgreement bool
}

func CalibrateConfidence(signals ConfidenceSignals) model.Confidence {
	if signals.Base == model.ConfidenceHigh {
		return model.ConfidenceHigh
	}
	if signals.EvidenceCount >= 3 || (signals.EvidenceCount >= 2 && (signals.ResolverCount >= 2 || signals.CrossLayerAgreement)) {
		return model.ConfidenceHigh
	}
	if signals.EvidenceCount >= 2 || signals.ResolverCount >= 2 || signals.ControlCorroborated || signals.CrossLayerAgreement {
		return model.ConfidenceMedium
	}
	return signals.Base
}
