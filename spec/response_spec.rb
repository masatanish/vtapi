require 'spec_helper'

describe VtAPI::Response do
  context 'with sample file_report response' do
    let(:sample_response) {
      "{\"scans\":{\"McAfee\":{\"detected\":false,\"version\":\"5.400.0.1158\",\"result\":null,\"update\":\"20130512\"},\"Symantec\":{\"detected\":true,\"version\":\"20121.3.0.76\",\"result\":\"Android.ZertSecurity\",\"update\":\"20130512\"},\"Kaspersky\":{\"detected\":true,\"version\":\"9.0.0.837\",\"result\":\"HEUR:Trojan-Banker.AndroidOS.Zitmo.a\",\"update\":\"20130512\"},\"TrendMicro\":{\"detected\":false,\"version\":\"9.740.0.1012\",\"result\":null,\"update\":\"20130512\"},\"Microsoft\":{\"detected\":false,\"version\":\"1.9402\",\"result\":null,\"update\":\"20130512\"}},\"scan_id\":\"00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98-1368320515\",\"sha1\":\"e1b727b3e9336033606df79eeba03dd218b56c20\",\"resource\":\"00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98\",\"response_code\":1,\"scan_date\":\"2013-05-12 01:01:55\",\"permalink\":\"https://www.virustotal.com/file/00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98/analysis/1368320515/\",\"verbose_msg\":\"Scan finished, scan information embedded in this object\",\"total\":46,\"positives\":22,\"sha256\":\"00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98\",\"md5\":\"1cf41bdc0fdd409774eb755031a6f49d\"}"
    }
    let(:sample_json) { JSON.parse(sample_response) }
    let(:response) { VtAPI::Response.new(sample_json) }
    

    describe '#md5' do
      it { expect(response.md5).to eq '1cf41bdc0fdd409774eb755031a6f49d' }
    end

    describe '#sha1' do
      it { expect(response.sha1).to eq 'e1b727b3e9336033606df79eeba03dd218b56c20' }
    end

    describe '#sha256' do
      it { expect(response.sha256).to eq '00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98' }
    end

    describe '#scan_date' do
      it { expect(response.scan_date).to be_a Time }
    end

    describe '#total' do
      it { expect(response.total).to eq 46 }
    end

    describe '#positives' do
      it { expect(response.positives).to eq 22 }
    end

    describe '#scan_id' do
      it { expect(response.scan_id).to eq '00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98-1368320515' }
    end

    describe '#resource' do
      it { expect(response.resource).to eq '00ce460c8b337110912066f746731a916e85bf1d7f4b44f09ca3cc39f9b52a98' }
    end

    describe '#keys' do
      it { expect(response.keys).to match_array ['scans', 'scan_id', 'sha1', 'resource', 'response_code', 'scan_date', 'permalink', 'verbose_msg', 'total', 'positives', 'sha256', 'md5'] }
    end

    describe '#positive_brands' do
      subject { response.positive_brands }
      it { expect(subject).to match_array ["Kaspersky", "Symantec"] }
    end

    describe '#positive_threats' do
      subject { response.positive_threats }
      it { expect(subject).to eq({"Symantec"=>"Android.ZertSecurity", "Kaspersky"=>"HEUR:Trojan-Banker.AndroidOS.Zitmo.a"}) }
    end

    describe '#scan_results' do
      subject { response.scan_results }
      it { expect(subject).to eq({"McAfee"=>nil, "Symantec"=>"Android.ZertSecurity", "Kaspersky"=>"HEUR:Trojan-Banker.AndroidOS.Zitmo.a", "TrendMicro"=>nil, "Microsoft"=>nil}) }
    end
  end

  context 'with no scan result' do
    describe '#positive_brands' do
      pending 'not implemented yet'
    end

    describe '#positive_threats' do
      pending 'not implemented yet'
    end
  end

  describe '.parse' do
    subject { VtAPI::Response.parse(response) }
    context 'assigns single response' do
      let(:response) { '{"md5":"1cf41bdc0fdd409774eb755031a6f49d"}' }
      it { expect(subject).to be_a VtAPI::Response }
      it { expect(subject.md5).to eq "1cf41bdc0fdd409774eb755031a6f49d" }
    end

    context 'assigns array response' do
      subject {VtAPI::Response.parse(response) }
      let(:response) { '[{"md5":"1cf41bdc0fdd409774eb755031a6f49d"}, {"md5":"1eef5bdc64241652f8a0df0c2dc92df6"}]' }
      it { expect(subject).to be_a Array }
      it { expect(subject).to have(2).items }

      context 'about first object' do
        subject {VtAPI::Response.parse(response).first }
        it { expect(subject).to be_a VtAPI::Response }
      end
    end
  end
end
