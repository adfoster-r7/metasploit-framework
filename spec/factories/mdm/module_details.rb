FactoryBot.modify do
  factory :mdm_module_detail do
    transient do
      root do
        Metasploit::Framework.root
      end
    end
  end
end
