load('ext://restart_process', 'docker_build_with_restart')

settings = {
    "deploy_cert_manager": False,
    "allowed_contexts": ["kind-kind"],
    # "trigger_mode": "",
    "registry": "localhost:5000",
    "namespace": "default-tilt-component",
    "component_paths": [],
    "enabled_components": [],
    "components": {},
    "build": {},
}

# Load ./tilt-settings.yaml to allow overriding settings.
tilt_file = "./tilt-settings.yaml" if os.path.exists("./tilt-settings.yaml") else "./tilt-settings.json"
settings.update(read_yaml(
    tilt_file,
    default = {},
))

# prevent accidentally developing on production
allow_k8s_contexts(settings.get("allowed_contexts"))
default_registry(settings.get("registry"))

# load external components
for path in settings.get("component_paths"):
    component_path = os.path.abspath(path)
    file = component_path + "/tilt-component.yaml"
    if not os.path.exists(file):
        fail("Failed to load component at %s. No tilt-component.yaml found" % file)
    ext_comps = read_yaml(file)
    if type(ext_comps) != type([]):
        ext_comps = [ext_comps]
    for ext_comp in ext_comps:
        name = ext_comp["name"]
        # we'll override the external component definition with what's specified in settings. This
        # way it's possible to override configuration for all components from a single tilt-settings.yaml file.
        component = settings["components"].get(name, {})
        # we'll shallow-merge 'debug' first to avoid deep merging
        component["debug"] = ext_comp.get("debug", {}) | component.get("debug", {})
        component = ext_comp | component
        component["path"] = component_path
        settings["components"][name] = component

print("applied tilt settings:\n")
print(encode_yaml_stream([settings]))

os_arch = str(local("go env GOARCH")).rstrip("\n")
build_env = "CGO_ENABLED=0 GOOS=linux GOARCH={arch}".format(
    arch = os_arch,
)
gcflags = ""


def parse_env_file(path):
    env = {}
    path = os.path.abspath(path)
    for line in str(read_file(path)).splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"')
    return env

def prefix_paths(paths, prefix):
    return [ os.path.join(prefix, p) for p in paths ]

def render_manifests(comp, image_name):

    ns = comp.get("namespace", settings["namespace"])

    k8s_yaml(blob("""
apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
""".format(namespace=ns)),allow_duplicates=True)

    chart_path = comp.get("chart_path", "/chart")
    if comp.get("helm", False):
        rendered = helm(
            comp["path"] + "/" + chart_path,
            name = comp["name"],
            namespace = ns,
        )
        manifests = decode_yaml_stream(rendered)
    else:
        local("make kustomize", dir = comp["path"])
        rendered = local(
            'cd config/manager; ../../bin/kustomize edit set image controller='.format(
                version=versions["KUSTOMIZE_VERSION"]),
            + image_name + '; cd ../..; bin/kustomize build config/default'.format(
                version=versions["KUSTOMIZE_VERSION"]),
            dir = comp["path"]
        )
        manifests = decode_yaml_stream(rendered)

    # prepare container for hot reload and debugging, apply args
    for i, o in enumerate(manifests):
        # set configured namespace for all namespaced resources
        if o["metadata"].get("namespace", False):
            o["metadata"]["namespace"] = ns

        if (
            o["kind"] == "Deployment"
            and o["metadata"]["name"] in (
                comp.get("deployment_name_controller_manager", comp["name"] + "-controller-manager"),
                comp.get("deployment_name_webhook_server", comp["name"] + "-webhook-server")
            )
        ):
            debug_settings = comp.get("debug", {"enabled": False})

            container = o["spec"]["template"]["spec"]["containers"][0]
            container["image"] = image_name

            # disable security features to enable hot reloading
            o["spec"]["template"]["spec"].pop("securityContext", None)

            # disable probes so the pod doesn't get terminated during debugging
            container.pop("livenessProbe", None)
            container.pop("readinessProbe", None)
            # add debug port if set
            if debug_settings.get("port", 0) != 0:
                container["ports"] = [{"containerPort": debug_settings.get("port")}]

            # set local environment specific envs (e.g. proxy configs)
            envs = settings.get("env", None)
            if envs != None:
                container["env"].extend(envs)

            # set component specific container envs
            envs = comp.get("env", None)
            if envs != None:
                container["env"].extend(envs)

            args = container["args"]
            remove_flags = ["--leader-elect", "--health-probe-bind-address=:8081"]
            args = [a for a in args if a not in remove_flags]
            if comp.get("add_flags", []):
                args = args + comp["add_flags"]
            container["args"] = args

            cmd = container["command"]
            new_cmd = ["sh", "/start.sh"] # use hot reload script
            if debug_settings.get("enabled", False):
                new_cmd.extend(["/dlv", "exec", "--accept-multiclient", "--api-version=2", "--headless=true",
                                "--continue=%s" % debug_settings.get("continue", "true"),
                                ])
                if debug_settings.get("port", False):
                    new_cmd.append("--listen=:%s" % debug_settings.get("port"))
                # insert '--' after the binary so dlv passes further flags to the binary
                cmd.insert(1, "--")

                # set memory limit to 1Gi when debugging with delve
                container["resources"]["limits"]["memory"] = "1Gi"

            container["command"] = new_cmd + cmd
        manifests[i] = o
    return encode_yaml_stream(manifests)

def build_binary(comp, build_out_path):
    generate_res_name = comp["name"] + " generate"
    local("make controller-gen", dir = comp["path"])
    local_resource(
        generate_res_name,
        cmd = '{path}/bin/controller-gen-{version} object:headerFile="hack/boilerplate.go.txt" paths="{path}/..."'.format(
            path=comp["path"],
            version=versions["CONTROLLER_TOOLS_VERSION"]),
        dir = comp["path"],
        #deps=prefix_paths(["/api"], comp["path"]),
        trigger_mode = TRIGGER_MODE_MANUAL,
        # ignore=prefix_paths(['*/*/zz_generated.deepcopy.go'], comp["path"]),
        labels = comp["name"]
    )

    main_path = comp.get("main_path", "cmd/main.go")
    local_resource(
        comp["name"] + " binary",
        cmd = "{build_env} go build -gcflags '{gcflags}' -tags=crds -o {path}/bin/{binary_name} {main}".format(
            build_env = build_env,
            gcflags = gcflags,
            path = build_out_path,
            main = main_path,
            binary_name = comp.get("binary_name", "manager")
        ),
        dir = comp["path"],
        deps=prefix_paths(comp["live_update_deps"], comp["path"]),
        # ignore=prefix_paths(['*/*/zz_generated.deepcopy.go'], comp["path"]),
        resource_deps=[generate_res_name],
        labels = ["0_binaries", comp["name"]]
    )

dockerfile_contents = """
FROM golang:1.25 as tilt-helper
RUN  export http_proxy={proxy} \
  && export https_proxy={proxy} \
  && export no_proxy={no_proxy} \
  && export GOPROXY=direct \
  && go install github.com/go-delve/delve/cmd/dlv@latest \
  && chmod +x /go/bin/dlv

FROM gcr.io/distroless/base:debug as tilt
WORKDIR /
COPY --from=tilt-helper /go/bin/dlv .
COPY ./start.sh /start.sh
COPY ./restart.sh /restart.sh
COPY ./{binary_name} /{binary_name}
"""

def build_container(comp, build_out_path, image_name):
    # build a docker image
    binary_name = comp.get("binary_name", "manager")
    build_path = build_out_path + "/bin"
    print(os.getcwd())
    local("cp " + os.getcwd() + "/hack/tilt/* " + build_path)
    docker_build(
        ref = image_name,
        context = build_path,
        dockerfile_contents = dockerfile_contents.format(
            binary_name = binary_name,
            proxy = settings.get("build", {}).get("proxy", ""),
            no_proxy = settings.get("build", {}).get("no_proxy", ""),
        ),
        target = "tilt",
        live_update = [
            sync(build_out_path + "/bin/", "/"),
            run("sh /restart.sh"),
        ],
    )

def handle_component(comp):
    build_out_path = comp["path"] + "/.tiltbuild"
    image_name = "localhost:5000/t-caas/{name}".format(name=comp["name"])

    local("mkdir -p " + build_out_path + "/bin")
    build_binary(comp, build_out_path)

    build_container(comp, build_out_path, image_name)

    local("cd " + comp["path"] + "; make install")

    # add pot. configured additional CRDs
    addCRDdirs = comp.get("additionalCRDs", [])
    for addCRDdir in addCRDdirs:
      files = str(local("find {dir} -type f -name '*.yml' -or -name '*.yaml'".format(dir=addCRDdir)))
      for file in files.split("\n")[:-1]:
        k8s_yaml(file)

    manifests = render_manifests(comp, image_name)
    k8s_yaml(manifests)

    forwards = []
    debug_config = comp.get("debug", {})
    if debug_config.get("enabled", False):
        p = debug_config.get("port", 30000)
        forwards.append(port_forward(p, p, 'debugger'))

    k8s_resource(
        workload = comp.get("deployment_name_controller_manager", comp["name"] + "-controller-manager"),
        labels = ["0_deployments", comp["name"]],
        port_forwards=forwards
    )
    k8s_resource(
        workload = comp.get("deployment_name_webhook_server", comp["name"] + "-webhook-server"),
        labels = ["0_deployments", comp["name"]],
        port_forwards=forwards
    )

versions = parse_env_file("versions.env")

for comp_name in settings.get("enabled_components", []):
    comp = settings["components"].get(comp_name, False)
    if comp:
        handle_component(comp)
