module VulnChaser
  class SecurityAnalyzer
    def initialize(api_key:)
      @api_key = api_key
      @client = OpenAI::Client.new(access_token: api_key)
    end

    def analyze_trace(trace_data)
      prompt = generate_security_prompt(trace_data)
      
      response = @client.chat(
        parameters: {
          model: "gpt-4",
          messages: [{ role: "user", content: prompt }],
          temperature: 0.7
        }
      )

      parse_response(response)
    end

    private

    def generate_security_prompt(trace_data)
      <<~PROMPT
        以下のRailsアプリケーションの処理フローを解析し、セキュリティ上の脆弱性を特定してください:

        エンドポイント: #{trace_data[:endpoint]}
        処理フロー:
        #{JSON.pretty_generate(trace_data[:traces])}

        以下の観点で解析してください:
        1. SQL インジェクション
        2. XSS脆弱性
        3. CSRF対策
        4. 認可の問題
        5. その他のセキュリティリスク
      PROMPT
    end
  end
end