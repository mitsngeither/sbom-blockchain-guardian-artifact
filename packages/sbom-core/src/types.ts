// Raw CycloneDX SBOM
export type SBOMHash = {
    alg: string;
    content: string;
};

export type SBOMLicense = {
    license?: {
        id?: string;
        name?: string;
    };
    expression?: string;
};

export type ExternalReference = {
    type: string;
    url: string;
    comment?: string;
    hashes?: SBOMHash[];
};

export type CycloneDXComponent = {
    "bom-ref"?: string;
    // Required by CycloneDX but often missing in practice; the parser fills it in.
    type?: string;
    name: string;
    group?: string;
    version?: string;
    author?: string;
    description?: string;
    purl?: string;
    hashes?: SBOMHash[];
    licenses?: SBOMLicense[];
    externalReferences?: ExternalReference[];
    capabilities?: string[];
    properties?: Array<{
        name: string;
        value: string;
    }>;
};

export type CycloneDXDependency = {
    ref: string;
    dependsOn?: string[];
};

export type CycloneDXSBOM = {
    bomFormat: string;
    specVersion: string;
    version: number;
    serialNumber?: string;
    metadata?: {
        timestamp?: string;
        tools?: {
            components?: CycloneDXComponent[];
        };
        component?: CycloneDXComponent;
    };
    components?: CycloneDXComponent[];
    dependencies?: CycloneDXDependency[];
};

// Flattened SBOM
export type FlattenedSBOMComponent = {
    key: string;
    identity: string;

    bomRef: string;
    type: string;
    name: string;
    group?: string;
    version: string;
    purl?: string;

    licenseIds: string[];
    licenseExpressions: string[];
    hashes: SBOMHash[];
    externalUrls: string[];

    dependencies: string[];
    capabilities: string[];
};

export type FlattenedSBOM = {
    bomFormat: string;
    specVersion: string;
    version: number;
    serialNumber?: string;
    timestamp?: string;

    components: FlattenedSBOMComponent[];
    componentMap: Record<string, FlattenedSBOMComponent>;
    componentByBomRef: Record<string, FlattenedSBOMComponent>;
};
