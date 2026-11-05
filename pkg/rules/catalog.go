// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

// Tool: un programma noto che legge segreti per mestiere, con le regole di cui ha bisogno.
// Il catalogo non autorizza niente da solo: la GUI propone, l'utente conferma, e il demone
// accetta comunque solo binari di root (vedi Trusted).
type Tool struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Names []string `json:"names"` // nomi dell'eseguibile (il primo trovato vale)
	Rules []string `json:"rules"` // regole da estendere
	Reads string   `json:"reads"` // perche' ha bisogno di quel segreto
}

// Tools: i programmi che in audit risultano toccare i segreti dei flussi Kubernetes/container.
// Le regole sono quelle dei gruppi predefiniti (cloud-creds, dev-tokens, ...).
var Tools = []Tool{
	{"k3d", "k3d", []string{"k3d"}, []string{"dev-tokens"}, "legge ~/.docker/config.json per i registry"},
	{"helm", "Helm", []string{"helm"}, []string{"cloud-creds", "dev-tokens"}, "usa il kubeconfig e le credenziali dei registry OCI"},
	{"k9s", "k9s", []string{"k9s"}, []string{"cloud-creds"}, "legge il kubeconfig per mostrare i cluster"},
	{"oh-my-posh", "oh-my-posh", []string{"oh-my-posh"}, []string{"cloud-creds"}, "il segmento Kubernetes del prompt legge il kubeconfig"},
	{"kubectx", "kubectx / kubens", []string{"kubectx", "kubens"}, []string{"cloud-creds"}, "cambia contesto e namespace nel kubeconfig"},
	{"stern", "stern", []string{"stern"}, []string{"cloud-creds"}, "segue i log dei pod con il kubeconfig"},
	{"flux", "Flux", []string{"flux"}, []string{"cloud-creds"}, "parla con il cluster via kubeconfig"},
	{"argocd", "Argo CD", []string{"argocd"}, []string{"cloud-creds"}, "usa il kubeconfig per l'accesso al cluster"},
	{"kind", "kind", []string{"kind"}, []string{"cloud-creds", "dev-tokens"}, "scrive il kubeconfig e usa docker"},
	{"minikube", "minikube", []string{"minikube"}, []string{"cloud-creds", "dev-tokens"}, "scrive il kubeconfig e usa docker"},
	{"skaffold", "Skaffold", []string{"skaffold"}, []string{"cloud-creds", "dev-tokens"}, "deploy sul cluster e push sui registry"},
	{"lazydocker", "lazydocker", []string{"lazydocker"}, []string{"dev-tokens"}, "legge la configurazione di docker"},
	{"gh", "GitHub CLI", []string{"gh"}, []string{"dev-tokens"}, "legge il token in ~/.config/gh"},
	{"glab", "GitLab CLI", []string{"glab"}, []string{"dev-tokens"}, "legge il token in ~/.config/glab-cli"},
}

// ToolByID cerca nel catalogo.
func ToolByID(id string) (Tool, bool) {
	for _, t := range Tools {
		if t.ID == id {
			return t, true
		}
	}
	return Tool{}, false
}
