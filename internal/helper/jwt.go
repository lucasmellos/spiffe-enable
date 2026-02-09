package helper

import (
	"strings"

	constants "github.com/cofide/spiffe-enable/internal/const"
	corev1 "k8s.io/api/core/v1"
)

// ParseJWTConfigFromAnnotations extracts JWT SVID configuration from pod annotations
func ParseJWTConfigFromAnnotations(annotations map[string]string) []SPIFFEHelperJWTConfig {
	var jwtConfigs []SPIFFEHelperJWTConfig

	audience, hasAudience := annotations[constants.HelperJWTAudienceAnnotation]
	filename, hasFilename := annotations[constants.HelperJWTFilenameAnnotation]

	// Only create JWT config if audience is specified
	if !hasAudience || audience == "" {
		return jwtConfigs
	}

	// Default filename if not specified
	if !hasFilename || filename == "" {
		filename = "tokens/token"
	}

	jwtConfig := SPIFFEHelperJWTConfig{
		JWTAudience:     audience,
		JWTSVIDFilename: filename,
		// Important: keep this non-nil so HCL encoding emits `[]` not `null`.
		JWTExtraAudiences: []string{},
	}

	// Parse extra audiences if present (comma-separated)
	if extraAudiences, hasExtra := annotations[constants.HelperJWTExtraAudiencesAnnotation]; hasExtra && extraAudiences != "" {
		rawAudiences := strings.Split(extraAudiences, ",")
		audiences := make([]string, 0, len(rawAudiences))
		for _, a := range rawAudiences {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			audiences = append(audiences, a)
		}
		jwtConfig.JWTExtraAudiences = audiences
	}

	jwtConfigs = append(jwtConfigs, jwtConfig)
	return jwtConfigs
}

// EnsureCertVolumeMount adds the cert directory volume mount to the container
// if it doesn't already exist
func EnsureCertVolumeMount(container *corev1.Container, certPath string) bool {
	volumeMount := corev1.VolumeMount{
		Name:      constants.SPIFFEEnableCertVolumeName,
		MountPath: certPath,
		ReadOnly:  true,
	}

	// Check if this volume mount already exists
	for _, vm := range container.VolumeMounts {
		if vm.Name == constants.SPIFFEEnableCertVolumeName && vm.MountPath == certPath {
			return false // Already exists
		}
	}

	container.VolumeMounts = append(container.VolumeMounts, volumeMount)
	return true
}
