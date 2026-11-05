import { deployment, pod, sidecarPod, type Obj } from "./template-harness.js";

// Control-plane objects as the istio-discovery chart and `istioctl tag set` render them
// (manifests/charts/istio-control/istio-discovery/templates/mutatingwebhook.yaml and
// revision-tags-mwc.yaml): one MutatingWebhookConfiguration per revision or tag, with the
// rev.namespace / rev.object hooks and, for the default revision or a "default" tag, the
// namespace / object hooks that serve istio-injection=enabled.

const ISTIO_NS = "istio-system";

function hook(prefix: string, service: string, namespaceSelector: Obj, objectSelector: Obj, failurePolicy: string): Obj {
  return {
    name: `${prefix}sidecar-injector.istio.io`,
    clientConfig: { service: { name: service, namespace: ISTIO_NS, path: "/inject", port: 443 } },
    rules: [{ operations: ["CREATE"], apiGroups: [""], apiVersions: ["v1"], resources: ["pods"] }],
    failurePolicy,
    sideEffects: "None",
    admissionReviewVersions: ["v1"],
    namespaceSelector,
    objectSelector,
  };
}

const expr = (key: string, operator: string, values?: string[]) => ({ key, operator, ...(values ? { values } : {}) });

export interface InjectorOpts {
  /** Revision tag name: renders istio-revision-tag-<tag> pointing at `revision`. */
  tag?: string;
  /** Service the hooks call; defaults to istiod(-<revision>). */
  service?: string;
  failurePolicy?: "Fail" | "Ignore";
  /** As `istioctl tag set default` leaves the old default injector: selectors that never match. */
  deactivated?: boolean;
}

/** A sidecar-injector MutatingWebhookConfiguration for a revision ("" = the default revision) or a tag of it. */
export function injectorWebhook(revision: string, opts: InjectorOpts = {}): Obj {
  const service = opts.service ?? (revision ? `istiod-${revision}` : "istiod");
  const match = opts.tag ?? (revision || "default");
  const fp = opts.failurePolicy ?? "Fail";
  const notFalse = expr("sidecar.istio.io/inject", "NotIn", ["false"]);
  let webhooks: Obj[] = [
    hook("rev.namespace.", service, { matchExpressions: [expr("istio.io/rev", "In", [match]), expr("istio-injection", "DoesNotExist")] }, { matchExpressions: [notFalse] }, fp),
    hook("rev.object.", service, { matchExpressions: [expr("istio.io/rev", "DoesNotExist"), expr("istio-injection", "DoesNotExist")] }, { matchExpressions: [notFalse, expr("istio.io/rev", "In", [match])] }, fp),
  ];
  if (match === "default") {
    webhooks.push(
      hook("namespace.", service, { matchExpressions: [expr("istio-injection", "In", ["enabled"])] }, { matchExpressions: [notFalse] }, fp),
      hook("object.", service, { matchExpressions: [expr("istio-injection", "DoesNotExist"), expr("istio.io/rev", "DoesNotExist")] }, { matchExpressions: [expr("sidecar.istio.io/inject", "In", ["true"]), expr("istio.io/rev", "DoesNotExist")] }, fp),
    );
  }
  if (opts.deactivated) {
    const never = { matchLabels: { "istio.io/deactivated": "never-match" } };
    webhooks = webhooks.map((w) => ({ ...w, namespaceSelector: never, objectSelector: never }));
  }
  const name = opts.tag ? `istio-revision-tag-${opts.tag}` : `istio-sidecar-injector${revision ? `-${revision}` : ""}`;
  return {
    apiVersion: "admissionregistration.k8s.io/v1",
    kind: "MutatingWebhookConfiguration",
    metadata: { name, labels: { app: "sidecar-injector", "istio.io/rev": revision || "default", ...(opts.tag ? { "istio.io/tag": opts.tag } : {}) } },
    webhooks,
  };
}

/** The default-revision ValidatingWebhookConfiguration (base chart, or `istioctl tag set default`). */
export function defaultValidator(revision: string, opts: { failurePolicy?: "Fail" | "Ignore"; service?: string } = {}): Obj {
  return {
    apiVersion: "admissionregistration.k8s.io/v1",
    kind: "ValidatingWebhookConfiguration",
    metadata: { name: "istiod-default-validator", labels: { app: "istiod", "istio.io/rev": revision } },
    webhooks: [
      {
        name: "validation.istio.io",
        clientConfig: { service: { name: opts.service ?? (revision === "default" ? "istiod" : `istiod-${revision}`), namespace: ISTIO_NS, path: "/validate" } },
        ...(opts.failurePolicy ? { failurePolicy: opts.failurePolicy } : {}),
      },
    ],
  };
}

/**
 * A revision's own ValidatingWebhookConfiguration, istio-validator(-<rev>)-istio-system, as the
 * istio-discovery chart renders it: objectSelector istio.io/rev In [<rev>] (validatingwebhookconfiguration.yaml).
 */
export function revisionValidator(revision: string, opts: { failurePolicy?: "Fail" | "Ignore" } = {}): Obj {
  const rev = revision || "default";
  return {
    apiVersion: "admissionregistration.k8s.io/v1",
    kind: "ValidatingWebhookConfiguration",
    metadata: { name: `istio-validator${revision ? `-${revision}` : ""}-${ISTIO_NS}`, labels: { app: "istiod", "istio.io/rev": rev } },
    webhooks: [
      {
        name: "rev.validation.istio.io",
        clientConfig: { service: { name: revision ? `istiod-${revision}` : "istiod", namespace: ISTIO_NS, path: "/validate" } },
        failurePolicy: opts.failurePolicy ?? "Fail",
        objectSelector: { matchExpressions: [{ key: "istio.io/rev", operator: "In", values: [rev] }] },
      },
    ],
  };
}

/** A workload whose pod template carries `labels` (CronJob: spec.jobTemplate.spec.template). */
export function workload(kind: "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob", namespace: string, name: string, labels: Obj = { app: name }): Obj {
  const template = { metadata: { labels }, spec: { containers: [{ name: "app", image: "registry.example.com/app:2.0" }] } };
  const apiVersion = kind === "Job" || kind === "CronJob" ? "batch/v1" : "apps/v1";
  const spec = kind === "CronJob" ? { schedule: "0 * * * *", jobTemplate: { spec: { template } } } : { template };
  return { apiVersion, kind, metadata: { name, namespace }, spec };
}

/** A HorizontalPodAutoscaler for a revision's istiod Deployment. */
export function istiodHpa(revision: string): Obj {
  const name = revision ? `istiod-${revision}` : "istiod";
  return {
    apiVersion: "autoscaling/v2",
    kind: "HorizontalPodAutoscaler",
    metadata: { name, namespace: ISTIO_NS, labels: { app: "istiod", "istio.io/rev": revision || "default" } },
    spec: { scaleTargetRef: { apiVersion: "apps/v1", kind: "Deployment", name }, minReplicas: 1, maxReplicas: 5 },
  };
}

/** An istiod pod of a revision in phase Running whose discovery container is not ready (CrashLoopBackOff). */
export function crashingIstiodPod(revision: string): Obj {
  const rev = revision || "default";
  const name = revision ? `istiod-${revision}` : "istiod";
  return {
    ...pod(ISTIO_NS, `${name}-7c9d8f6b5-crash`, { app: "istiod", "istio.io/rev": rev }, [{ name: "discovery" }]),
    status: {
      phase: "Running",
      conditions: [{ type: "Ready", status: "False" }],
      containerStatuses: [{ name: "discovery", ready: false, restartCount: 42, state: { waiting: { reason: "CrashLoopBackOff" } } }],
    },
  };
}

/** A revision's istiod Deployment, its Service and (unless replicas is 0) one Running pod, or a crash-looping one. */
export function controlPlane(revision: string, opts: { replicas?: number; crashing?: boolean } = {}): Obj[] {
  const rev = revision || "default";
  const name = revision ? `istiod-${revision}` : "istiod";
  const labels = { app: "istiod", "istio.io/rev": rev };
  const replicas = opts.replicas ?? 1;
  const objs: Obj[] = [
    deployment(ISTIO_NS, name, { labels, replicas, containers: [{ name: "discovery", image: "docker.io/istio/pilot:1.31.2" }] }),
    { apiVersion: "v1", kind: "Service", metadata: { name, namespace: ISTIO_NS, labels }, spec: { selector: labels, ports: [{ name: "https-webhook", port: 443 }] } },
    configMap(ISTIO_NS, revision ? `istio-${revision}` : "istio", rev, { mesh: "rootNamespace: istio-system\n" }),
    configMap(ISTIO_NS, revision ? `istio-sidecar-injector-${revision}` : "istio-sidecar-injector", rev, { config: "policy: enabled\n", values: "{}" }),
  ];
  if (opts.crashing) objs.push(crashingIstiodPod(revision));
  else if (replicas > 0) objs.push({ ...pod(ISTIO_NS, `${name}-5d8f7c6b9-x2k9p`, labels, [{ name: "discovery" }]), status: { phase: "Running" } });
  return objs;
}

export function configMap(namespace: string, name: string, revision: string | undefined, data: Obj): Obj {
  return { apiVersion: "v1", kind: "ConfigMap", metadata: { name, namespace, labels: revision ? { "istio.io/rev": revision } : {} }, data };
}

/** The tag Service `istioctl tag set` creates from 1.28 (istiod-revision-tag-<tag>). */
export function tagService(tag: string, revision: string): Obj {
  return {
    apiVersion: "v1",
    kind: "Service",
    metadata: { name: `istiod-revision-tag-${tag}`, namespace: ISTIO_NS, labels: { app: "istiod", "istio.io/rev": revision, "istio.io/tag": tag } },
    spec: { selector: { app: "istiod", "istio.io/rev": revision }, ports: [{ port: 443 }] },
  };
}

/** A Running pod injected by `revision` (sidecar.istio.io/status names the revision). */
export function injectedPod(namespace: string, name: string, revision: string, labels: Obj = { app: name }): Obj {
  const p = sidecarPod(namespace, name, "1.31.2", labels) as { metadata: Obj };
  const status = JSON.stringify({ initContainers: ["istio-init"], containers: ["istio-proxy"], volumes: ["istio-envoy"], imagePullSecrets: null, revision });
  return { ...p, metadata: { ...p.metadata, annotations: { "sidecar.istio.io/status": status } }, status: { phase: "Running" } };
}

/** A Running application pod with no sidecar. */
export function plainPod(namespace: string, name: string, labels: Obj = { app: name }): Obj {
  return { ...pod(namespace, name, labels, [{ name: "app", image: "registry.example.com/app:2.0" }]), status: { phase: "Running" } };
}
