# -*- coding:binary -*-

RSpec.shared_examples_for 'Msf::Modules::VersionCompatibilityError' do
  let(:error) do
    begin
      subject.version_compatible!(module_path, module_reference_name)
    rescue Msf::Modules::VersionCompatibilityError => e
    end

    error
  end

  it 'should be raised' do
    expect do
      subject.version_compatible!(module_path, module_reference_name)
    end.to raise_error(Msf::Modules::VersionCompatibilityError)
  end

  it 'should include minimum API version' do
    expect(error.to_s).to include(minimum_api_version.to_s)
  end

  it 'should include minimum Core version' do
    expect(error.to_s).to include(minimum_core_version.to_s)
  end

  it 'should include module path' do
    expect(error.to_s).to include(module_path)
  end

  it 'should include module reference name' do
    expect(error.to_s).to include(module_reference_name)
  end
end
