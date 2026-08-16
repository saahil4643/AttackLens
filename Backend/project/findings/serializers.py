from rest_framework import serializers
from .models import Finding, FindingOccurrence, FindingEvidence

VALID_FINDING_STATUS_TRANSITIONS = {
    'OPEN': ['CONFIRMED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'RESOLVED'],
    'CONFIRMED': ['RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'],
    'FALSE_POSITIVE': ['OPEN'],
    'ACCEPTED_RISK': ['OPEN'],
    'RESOLVED': ['OPEN'],
}

class FindingEvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = FindingEvidence
        fields = [
            'id', 'finding', 'evidence_type', 'title', 'description', 
            'request', 'response', 'location', 'payload', 'code_snippet', 
            'metadata', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class FindingOccurrenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = FindingOccurrence
        fields = [
            'id', 'finding', 'scan_job', 'first_seen', 'last_seen', 'metadata'
        ]
        read_only_fields = ['id', 'first_seen', 'last_seen']


class FindingSerializer(serializers.ModelSerializer):
    evidence = FindingEvidenceSerializer(source='evidence_records', many=True, read_only=True)
    occurrences = FindingOccurrenceSerializer(many=True, read_only=True)

    class Meta:
        model = Finding
        fields = [
            'id', 'project', 'assessment', 'scan_job', 'testing_module', 'asset',
            'title', 'description', 'category', 'severity', 'confidence', 'status',
            'cvss_score', 'cwe', 'remediation', 'references', 'fingerprint',
            'metadata', 'evidence', 'occurrences', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'fingerprint', 'created_at', 'updated_at']

    def validate_title(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Finding title is required.")
        return value

    def validate_cvss_score(self, value):
        if value is not None and not (0.0 <= float(value) <= 10.0):
            raise serializers.ValidationError("CVSS score must be between 0.0 and 10.0.")
        return value

    def validate(self, attrs):
        # 1. Enforce status transition checks
        if self.instance and 'status' in attrs:
            old_status = self.instance.status
            new_status = attrs['status']
            if old_status != new_status:
                allowed = VALID_FINDING_STATUS_TRANSITIONS.get(old_status, [])
                if new_status not in allowed:
                    raise serializers.ValidationError(
                        {"status": f"Invalid status transition from '{old_status}' to '{new_status}'."}
                    )
        
        # 2. Enforce Project-Asset alignment
        project = attrs.get('project', self.instance.project if self.instance else None)
        asset = attrs.get('asset', self.instance.asset if self.instance else None)
        if asset and project and asset.project != project:
            raise serializers.ValidationError(
                {"asset": "Asset must belong to the selected project."}
            )
            
        return attrs
