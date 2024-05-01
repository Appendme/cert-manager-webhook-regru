package main

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var (
	GroupName     = os.Getenv("GROUP_NAME")
	regruUsername = os.Getenv("REGRU_USERNAME")
	regruPassword = os.Getenv("REGRU_PASSWORD")
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&regruDNSProviderSolver{},
	)
}

// regruDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type regruDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *regruDNSProviderSolver) Name() string {
	return "regru-dns"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *regruDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Hook Present: namespace=%s, zone=%s, fqdn=%s, key=%s", ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN, ch.Key)

	zone, err := getDomainFromZone(ch.ResolvedZone, ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("unable to initialize reg.ru client, because unable to get root zone from domains: %w", err)
	}

	client := NewRegruClient(regruUsername, regruPassword, zone)

	klog.Infof("present for entry=%s, domain=%s, key=%s", ch.ResolvedFQDN, zone, ch.Key)
	if err := client.createTXT(ch.ResolvedFQDN, ch.Key); err != nil {
		return fmt.Errorf("unable to create TXT record: %v", err)
	}

	// TODO: add code that sets a record in the DNS provider's console
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *regruDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Call function CleanUp: namespace=%s, zone=%s, fqdn=%s", ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	zone, err := getDomainFromZone(ch.ResolvedZone, ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("unable to initialize reg.ru client, because unable to get root zone from domains: %w", err)
	}

	client := NewRegruClient(regruUsername, regruPassword, zone)

	klog.Infof("delete entry=%s, domain=%s, key=%s", ch.ResolvedFQDN, zone, ch.Key)

	if err := client.deleteTXT(ch.ResolvedFQDN, ch.Key); err != nil {
		return fmt.Errorf("unable to delete TXT record: %v", err)
	}

	// TODO: add code that deletes a record from the DNS provider's console
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *regruDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Infof("Call function Initialize")

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		klog.Infof("Initialize error")
		return err
	}

	c.client = cl

	return nil
}
