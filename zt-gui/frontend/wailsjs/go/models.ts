export namespace ipc {
	
	export class RuleSummary {
	    name: string;
	    paths: string[];
	    allow: string[];
	
	    static createFrom(source: any = {}) {
	        return new RuleSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.paths = source["paths"];
	        this.allow = source["allow"];
	    }
	}
	export class SourceStat {
	    ip: string;
	    poison: number;
	    subnet: number;
	    total: number;
	    last_seen: string;
	
	    static createFrom(source: any = {}) {
	        return new SourceStat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.poison = source["poison"];
	        this.subnet = source["subnet"];
	        this.total = source["total"];
	        this.last_seen = source["last_seen"];
	    }
	}
	export class Status {
	    profile: string;
	    mode: string;
	    home: string;
	    hook_lsm: boolean;
	    xdp: string[];
	    protected: number;
	    allowed: number;
	    block_poisoning: boolean;
	    block_subnets: string[];
	    top_sources: SourceStat[];
	    rules: RuleSummary[];
	    time: string;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile = source["profile"];
	        this.mode = source["mode"];
	        this.home = source["home"];
	        this.hook_lsm = source["hook_lsm"];
	        this.xdp = source["xdp"];
	        this.protected = source["protected"];
	        this.allowed = source["allowed"];
	        this.block_poisoning = source["block_poisoning"];
	        this.block_subnets = source["block_subnets"];
	        this.top_sources = this.convertValues(source["top_sources"], SourceStat);
	        this.rules = this.convertValues(source["rules"], RuleSummary);
	        this.time = source["time"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

