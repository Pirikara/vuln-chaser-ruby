require 'spec_helper'

RSpec.describe VulnChaser::DataSanitizer do
  let(:sanitizer) { described_class.new }

  describe '#sanitize_params' do
    let(:params) do
      {
        'name' => 'John Doe',
        'password' => 'secret123',
        'email' => 'john@example.com',
        'credit_card' => '4111111111111111',
        'ssn' => '123-45-6789'
      }
    end

    it 'masks sensitive parameter keys' do
      result = sanitizer.sanitize_params(params)
      expect(result['password']).to eq('[FILTERED]')
      expect(result['name']).to eq('John Doe') # Non-sensitive preserved
    end

    it 'masks credit card numbers' do
      result = sanitizer.sanitize_params(params)
      expect(result['credit_card']).to eq('[CREDIT_CARD]')
    end

    it 'masks SSN patterns' do
      result = sanitizer.sanitize_params(params)
      expect(result['ssn']).to eq('[SSN]')
    end

    it 'partially masks email addresses' do
      result = sanitizer.sanitize_params(params)
      expect(result['email']).to match(/j\*\*\*e@example\.com/)
    end
  end

  describe '#sanitize_source_code' do
    let(:source_with_secrets) do
      'password = "secret123"; User.find_by_sql("SELECT * FROM users WHERE email = \'user@example.com\'")'
    end

    it 'masks quoted secrets in source code' do
      result = sanitizer.sanitize_source_code(source_with_secrets)
      expect(result).to include('[FILTERED]')
      expect(result).not_to include('secret123')
    end

    it 'masks email addresses in source code' do
      result = sanitizer.sanitize_source_code(source_with_secrets)
      expect(result).to match(/u\*\*\*r@example\.com/)
    end
  end

  describe '#sanitize_sql_query' do
    let(:sql_with_sensitive_data) do
      "SELECT * FROM users WHERE email = 'user@example.com' AND password = 'secretpass'"
    end

    it 'masks sensitive values in SQL while preserving structure' do
      result = sanitizer.sanitize_sql_query(sql_with_sensitive_data)
      expect(result).to include('SELECT * FROM users WHERE')
      expect(result).to include('[FILTERED]')
      expect(result).not_to include('secretpass')
    end
  end

  describe 'sensitive pattern detection' do
    describe 'credit card detection' do
      it 'detects various credit card formats' do
        cards = ['4111111111111111', '4111-1111-1111-1111', '4111 1111 1111 1111']
        cards.each do |card|
          result = sanitizer.sanitize_params({ 'card' => card })
          expect(result['card']).to eq('[CREDIT_CARD]')
        end
      end
    end

    describe 'SSN detection' do
      it 'detects various SSN formats' do
        ssns = ['123-45-6789', '123456789', '123 45 6789']
        ssns.each do |ssn|
          result = sanitizer.sanitize_params({ 'ssn' => ssn })
          expect(result['ssn']).to eq('[SSN]')
        end
      end
    end

    describe 'sensitive key detection' do
      let(:sensitive_keys) do
        %w[password secret token api_key private_key credential authorization]
      end

      it 'detects various sensitive parameter names' do
        sensitive_keys.each do |key|
          result = sanitizer.sanitize_params({ key => 'sensitive_value' })
          expect(result[key]).to eq('[FILTERED]')
        end
      end
    end
  end
end