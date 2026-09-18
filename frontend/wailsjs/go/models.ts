export namespace main {
	
	export class DebugPackage {
	    packageName: string;
	    label: string;
	
	    static createFrom(source: any = {}) {
	        return new DebugPackage(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.packageName = source["packageName"];
	        this.label = source["label"];
	    }
	}
	export class Device {
	    serial: string;
	    state: string;
	    model?: string;
	
	    static createFrom(source: any = {}) {
	        return new Device(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.serial = source["serial"];
	        this.state = source["state"];
	        this.model = source["model"];
	    }
	}
	export class DirectoryEntry {
	    name: string;
	    relativePath: string;
	    isDirectory: boolean;
	    size?: number;
	
	    static createFrom(source: any = {}) {
	        return new DirectoryEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.relativePath = source["relativePath"];
	        this.isDirectory = source["isDirectory"];
	        this.size = source["size"];
	    }
	}
	export class FileContent {
	    path: string;
	    content: string;
	    bytes: number;
	    lineCount: number;
	
	    static createFrom(source: any = {}) {
	        return new FileContent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.content = source["content"];
	        this.bytes = source["bytes"];
	        this.lineCount = source["lineCount"];
	    }
	}
	export class FilePreview {
	    path: string;
	    kind: string;
	    content?: string;
	    mime?: string;
	    type: string;
	    bytes: number;
	    lineCount?: number;
	
	    static createFrom(source: any = {}) {
	        return new FilePreview(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.kind = source["kind"];
	        this.content = source["content"];
	        this.mime = source["mime"];
	        this.type = source["type"];
	        this.bytes = source["bytes"];
	        this.lineCount = source["lineCount"];
	    }
	}

}

