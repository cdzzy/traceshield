/**
 * traceshield/src/policy_recipes.ts
 * OWASP MLSRP 合规策略库 — Policy Recipe Library
 *
 * 参考 Trending 项目 Daytona 的"安全隔离执行"理念，
 * 为 traceshield 提供开箱即用的 OWASP MLSRP 合规策略模板。
 * 灵感来源：Daytona "Secure and Elastic Infrastructure for Running AI-Generated Code"
 */

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  pattern?: RegExp;         // 内容模式匹配
  maxLength?: number;       // 输出长度限制
  allowedPatterns?: string[];
  blockedPatterns?: string[];
  rateLimit?: {
    maxPerMinute: number;
    maxPerHour: number;
  };
  requireApproval?: boolean;
}

export interface PolicyRecipe {
  id: string;
  name: string;
  standard: string;          // 合规标准，如 "OWASP MLSRP"
  version: string;
  description: string;
  rules: PolicyRule[];
  tags: string[];
}

/**
 * OWASP MLSRP（Machine Learning Security Risks）合规策略库。
 * 参考 OWASP AI Security 项目，为 AI Agent 提供开箱即用的安全策略模板。
 */
export class PolicyRecipes {
  /**
   * 获取 OWASP MLSRP 基础合规策略。
   * 覆盖数据隐私、输入验证、输出过滤三大核心领域。
   */
  static owaspMLSRPBase(): PolicyRecipe {
    return {
      id: "owasp-mlsrp-base-v1",
      name: "OWASP MLSRP 基础合规策略",
      standard: "OWASP MLSRP 2024",
      version: "1.0.0",
      description:
        "基于 OWASP Machine Learning Security Risks 的基础合规策略，涵盖数据隐私、模型安全、输出验证等核心控制点。",
      tags: ["owasp", "mlsrp", "compliance", "baseline"],
      rules: [
        // 1. 数据隐私规则
        {
          id: "privacy-001",
          name: "PII 检测与过滤",
          description: "检测并过滤个人身份信息（PII），包括邮箱、电话、身份证号等",
          severity: "critical",
          blockedPatterns: [
            /\b\d{15,18}\b/,           // 身份证号
            /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, // 邮箱
            /1[3-9]\d{9}/,              // 中国手机号
          ],
          requireApproval: true,
        },
        // 2. 提示注入防护
        {
          id: "security-001",
          name: "提示注入检测",
          description: "检测并阻止常见提示注入攻击模式",
          severity: "critical",
          blockedPatterns: [
            /ignore (previous|above|all) (instruction|constraints)/i,
            /forget (everything|all|what) you (know|were|have)/i,
            /system prompt/i,
          ],
        },
        // 3. 输出长度控制（防止资源耗尽）
        {
          id: "safety-001",
          name: "输出长度限制",
          description: "限制单次输出长度，防止资源过度消耗",
          severity: "medium",
          maxLength: 8192,
        },
        // 4. 频率限制
        {
          id: "rate-001",
          name: "API 频率限制",
          description: "防止高频调用导致服务不稳定",
          severity: "high",
          rateLimit: {
            maxPerMinute: 60,
            maxPerHour: 2000,
          },
        },
        // 5. 安全内容过滤
        {
          id: "safety-002",
          name: "有害内容过滤",
          description: "过滤暴力、犯罪、违规内容",
          severity: "critical",
          blockedPatterns: [
            /(hack|exploit|attack) (system|server|account|user)/i,
          ],
        },
      ],
    };
  }

  /**
   * Daytona 风格的安全沙箱策略。
   * "Secure and Elastic Infrastructure for Running AI-Generated Code"
   */
  static secureSandbox(): PolicyRecipe {
    return {
      id: "sandbox-daytona-style",
      name: "AI 代码执行沙箱策略",
      standard: "Daytona Secure Execution",
      version: "1.0.0",
      description:
        "基于 Daytona 安全执行理念，为 AI 生成的代码提供隔离执行环境，包括网络隔离、文件系统限制、系统调用过滤。",
      tags: ["sandbox", "secure-execution", "daytona"],
      rules: [
        {
          id: "sandbox-001",
          name: "网络访问限制",
          description: "禁止 AI 代码访问非白名单网络资源",
          severity: "critical",
          blockedPatterns: [
            /socket\s*\./,
            /http:\/\/(?!localhost)/,
            /ftp:\/\//,
          ],
          allowedPatterns: [
            /https:\/\/api\.openai\.com/,
            /https:\/\/api\.anthropic\.com/,
          ],
        },
        {
          id: "sandbox-002",
          name: "文件访问限制",
          description: "限制 AI 代码的文件系统访问范围",
          severity: "high",
          blockedPatterns: [
            /\.\.\//,  // 路径穿越
            /\/etc\//,
            /\/root\//,
            /~\//,
          ],
        },
        {
          id: "sandbox-003",
          name: "执行时间限制",
          description: "强制限制代码执行超时时间",
          severity: "high",
          maxLength: 1000, // 输出行数限制
        },
      ],
    };
  }

  /**
   * 获取所有可用策略配方。
   */
  static listRecipes(): { id: string; name: string; standard: string }[] {
    return [
      { id: "owasp-mlsrp-base-v1", name: this.owaspMLSRPBase().name, standard: "OWASP MLSRP 2024" },
      { id: "sandbox-daytona-style", name: this.secureSandbox().name, standard: "Daytona Secure Execution" },
    ];
  }
}

/**
 * 策略引擎：将策略配方应用到实际审计流程。
 * 参考 traceshield 的 lightweight audit trail 设计理念。
 */
export class PolicyEngine {
  private recipes: Map<string, PolicyRecipe> = new Map();
  private violations: Array<{ rule: PolicyRule; context: unknown }> = [];

  loadRecipe(recipe: PolicyRecipe): void {
    this.recipes.set(recipe.id, recipe);
  }

  evaluate(content: string, context?: unknown): {
    passed: boolean;
    violations: PolicyRule[];
    recipeName: string;
  } {
    const violations: PolicyRule[] = [];

    for (const recipe of this.recipes.values()) {
      for (const rule of recipe.rules) {
        if (this._violatesRule(content, rule)) {
          violations.push(rule);
        }
      }
    }

    this.violations.push(
      ...violations.map((v) => ({ rule: v, context }))
    );

    return {
      passed: violations.length === 0,
      violations,
      recipeName: Array.from(this.recipes.values())
        .map((r) => r.name)
        .join(", "),
    };
  }

  private _violatesRule(content: string, rule: PolicyRule): boolean {
    if (rule.blockedPatterns) {
      for (const pattern of rule.blockedPatterns) {
        if (pattern.test(content)) return true;
      }
    }
    if (rule.maxLength && content.length > rule.maxLength) return true;
    return false;
  }
}

