{{- define "soroban-scan.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "soroban-scan.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "soroban-scan.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "soroban-scan.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: scan
app.kubernetes.io/part-of: soroban-scan
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "soroban-scan.image" -}}
{{- $image := printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $image .Values.image.digest -}}
{{- else -}}
{{- $image -}}
{{- end -}}
{{- end -}}

{{- define "soroban-scan.sourceClaim" -}}
{{- default (printf "%s-source" (include "soroban-scan.fullname" .)) .Values.source.existingClaim -}}
{{- end -}}

{{- define "soroban-scan.reportsClaim" -}}
{{- default (printf "%s-reports" (include "soroban-scan.fullname" .)) .Values.reports.existingClaim -}}
{{- end -}}

{{- define "soroban-scan.podTemplate" -}}
metadata:
  labels:
    {{- include "soroban-scan.labels" . | nindent 4 }}
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    {{- toYaml .Values.podSecurityContext | nindent 4 }}
  {{- with .Values.imagePullSecrets }}
  imagePullSecrets:
    {{- range . }}
    - name: {{ . }}
    {{- end }}
  {{- end }}
  containers:
    - name: soroban-scan
      image: {{ include "soroban-scan.image" . }}
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      command: ["/bin/sh", "-c"]
      args:
        - >-
          exec soroban-scan scan /workspace/src
          --config /etc/soroban-scan/soroban-scan.toml
          --format json
          --output "/reports/${POD_NAME}.json"
          --fail-on {{ .Values.scan.failOn }}
          {{- range .Values.scan.extraArgs }} {{ . }}{{- end }}
      env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        {{- with .Values.extraEnv }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- with .Values.extraEnvFrom }}
      envFrom:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        {{- toYaml .Values.securityContext | nindent 8 }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      volumeMounts:
        - name: source
          mountPath: /workspace/src
          readOnly: true
        - name: reports
          mountPath: /reports
        - name: config
          mountPath: /etc/soroban-scan
          readOnly: true
  volumes:
    - name: source
      persistentVolumeClaim:
        claimName: {{ include "soroban-scan.sourceClaim" . }}
        readOnly: true
    - name: reports
      persistentVolumeClaim:
        claimName: {{ include "soroban-scan.reportsClaim" . }}
    - name: config
      configMap:
        name: {{ include "soroban-scan.fullname" . }}-config
        items:
          - key: soroban-scan.toml
            path: soroban-scan.toml
{{- end -}}
