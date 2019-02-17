defmodule ExtendedKeyTest do
  use ExUnit.Case
  doctest ExtendedKey

  alias ExtendedKey.Keypath

  describe "Test BIP32 vector 1" do
    @seed Base.decode16!("000102030405060708090a0b0c0d0e0f", case: :lower)

    test "Chain m" do
      expect_pubkey =
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

      expect_privkey =
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

      path = "m"

      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H" do
      expect_pubkey =
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

      expect_privkey =
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"

      path = "m/0H"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, true, :mainnet)
      check_key_properties(pubkey, true, true, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H/1" do
      expect_pubkey =
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

      expect_privkey =
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"

      path = "m/0H/1"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H/1/2H" do
      expect_pubkey =
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"

      expect_privkey =
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"

      path = "m/0H/1/2H"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, true, :mainnet)
      check_key_properties(pubkey, true, true, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H/1/2H/2" do
      expect_pubkey =
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"

      expect_privkey =
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"

      path = "m/0H/1/2H/2"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H/1/2H/2/1000000000" do
      expect_pubkey =
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"

      expect_privkey =
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

      path = "m/0H/1/2H/2/1000000000"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end
  end

  describe "Test BIP32 vector 2" do
    @seed Base.decode16!(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            case: :lower
          )

    test "Chain m" do
      expect_pubkey =
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

      expect_privkey =
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"

      path = "m"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0" do
      expect_pubkey =
        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

      expect_privkey =
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"

      path = "m/0"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0/2147483647H" do
      expect_pubkey =
        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"

      expect_privkey =
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"

      path = "m/0/2147483647H"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, true, :mainnet)
      check_key_properties(pubkey, true, true, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0/2147483647H/1" do
      expect_pubkey =
        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"

      expect_privkey =
        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"

      path = "m/0/2147483647H/1"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0/2147483647H/1/2147483646H" do
      expect_pubkey =
        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"

      expect_privkey =
        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"

      path = "m/0/2147483647H/1/2147483646H"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, true, :mainnet)
      check_key_properties(pubkey, true, true, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0/2147483647H/1/2147483646H/2" do
      expect_pubkey =
        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"

      expect_privkey =
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"

      path = "m/0/2147483647H/1/2147483646H/2"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end
  end

  describe "Test BIP32 vector 3" do
    @seed Base.decode16!(
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            case: :lower
          )

    test "Chain m" do
      expect_pubkey =
        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

      expect_privkey =
        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"

      path = "m"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, false, :mainnet)
      check_key_properties(pubkey, true, false, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H" do
      expect_pubkey =
        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"

      expect_privkey =
        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"

      path = "m/0H"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :mainnet, path)

      check_key_properties(privkey, false, true, :mainnet)
      check_key_properties(pubkey, true, true, :mainnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end
  end

  describe "Test BIP32 vector 1 - Testnet" do
    @seed Base.decode16!("000102030405060708090a0b0c0d0e0f", case: :lower)

    test "Chain m" do
      expect_pubkey =
        "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"

      expect_privkey =
        "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m"

      path = "m"

      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :testnet, path)

      check_key_properties(privkey, false, false, :testnet)
      check_key_properties(pubkey, true, false, :testnet)
      
      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H" do
      expect_pubkey =
        "tpubD8eQVK4Kdxg3gHrF62jGP7dKVCoYiEB8dFSpuTawkL5YxTus5j5pf83vaKnii4bc6v2NVEy81P2gYrJczYne3QNNwMTS53p5uzDyHvnw2jm"

      expect_privkey =
        "tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9"

      path = "m/0H"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :testnet, path)

      check_key_properties(privkey, false, true, :testnet)
      check_key_properties(pubkey, true, true, :testnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H/1" do
      expect_pubkey =
        "tpubDApXh6cD2fZ7WjtgpHd8yrWyYaneiFuRZa7fVjMkgxsmC1QzoXW8cgx9zQFJ81Jx4deRGfRE7yXA9A3STsxXj4CKEZJHYgpMYikkas9DBTP"

      expect_privkey =
        "tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q"

      path = "m/0H/1"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :testnet, path)

      check_key_properties(privkey, false, false, :testnet)
      check_key_properties(pubkey, true, false, :testnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H/1/2H" do
      expect_pubkey =
        "tpubDDRojdS4jYQXNugn4t2WLrZ7mjfAyoVQu7MLk4eurqFCbrc7cHLZX8W5YRS8ZskGR9k9t3PqVv68bVBjAyW4nWM9pTGRddt3GQftg6MVQsm"

      expect_privkey =
        "tprv8gjmbDPpbAirVSezBEMuwSu1Ci9EpUJWKokZTYccSZSomNMLytWyLdtDNHRbucNaRJWWHANf9AzEdWVAqahfyRjVMKbNRhBmxAM8EJr7R15"

      path = "m/0H/1/2H"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :testnet, path)

      check_key_properties(privkey, false, true, :testnet)
      check_key_properties(pubkey, true, true, :testnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H/1/2H/2" do
      expect_pubkey =
        "tpubDFfCa4Z1v25WTPAVm9EbEMiRrYwucPocLbEe12BPBGooxxEUg42vihy1DkRWyftztTsL23snYezF9uXjGGwGW6pQjEpcTpmsH6ajpf4CVPn"

      expect_privkey =
        "tprv8iyAReWmmePqZv8hsVZzpx4KHXRyT4chmHdriW95m11R8Tyi3fDLYDM93bq4NGn1V6eCu5cE3zSQ6hPd31F2ApKXkZgTyn1V78pHjkq1V2v"

      path = "m/0H/1/2H/2"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :testnet, path)

      check_key_properties(privkey, false, false, :testnet)
      check_key_properties(pubkey, true, false, :testnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end

    test "Chain m/0H/1/2H/2/1000000000" do
      expect_pubkey =
        "tpubDHNy3kAG39ThyiwwsgoKY4iRenXDRtce8qdCFJZXPMCJg5dsCUHayp84raLTpvyiNA9sXPob5rgqkKvkN8S7MMyXbnEhGJMW64Cf4vFAoaF"

      expect_privkey =
        "tprv8kgvuL81tmn36Fv9z38j8f4K5m1HGZRjZY2QxnXDy5PuqbP6a5TzoKWCgTcGHBu66W3TgSbAu2yX6sPza5FkHmy564Sh6gmCPUNeUt4yj2x"

      path = "m/0H/1/2H/2/1000000000"
      {privkey, pubkey} = derive_key_pair_from_seed(@seed, :testnet, path)

      check_key_properties(privkey, false, false, :testnet)
      check_key_properties(pubkey, true, false, :testnet)

      assert privkey === expect_privkey
      assert pubkey === expect_pubkey
    end
  end

  describe "Private key derivation vector 1" do
    @master_priv "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

    test "Chain m" do
      expect_privkey =
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

      path = "m"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0" do
      expect_privkey =
        "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R"

      path = "m/0"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0/1" do
      expect_privkey =
        "xprv9ww7sMFLzJMzy7bV1qs7nGBxgKYrgcm3HcJvGb4yvNhT9vxXC7eX7WVULzCfxucFEn2TsVvJw25hH9d4mchywguGQCZvRgsiRaTY1HCqN8G"

      path = "m/0/1"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0/1/2" do
      expect_privkey =
        "xprv9xrdP7iD2L1YZCgR9AecDgpDMZSTzP5KCfUykGXgjBxLgp1VFHsEeL3conzGAkbc1MigG1o8YqmfEA2jtkPdf4vwMaGJC2YSDbBTPAjfRUi"

      path = "m/0/1/2"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0/1/2/2" do
      expect_privkey =
        "xprvA2J8Hq4eiP7xCEBP7gzRJGJnd9CHTkEU6eTNMrZ6YR7H5boik8daFtDZxmJDfdMSKHwroCfAfsBKWWidRfBQjpegy6kzXSkQGGoMdWKz5Xh"

      path = "m/0/1/2/2"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0/1/2/2/1000000000" do
      expect_privkey =
        "xprvA3XhazxncJqJsQcG85Gg61qwPQKiobAnWjuPpjKhExprZjfse6nErRwTMwGe6uGWXPSykZSTiYb2TXAm7Qhwj8KgRd2XaD21Styu6h6AwFz"

      path = "m/0/1/2/2/1000000000"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end
  end

  describe "Private key derivation vector 2" do
    @master_priv "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"

    test "Chain m" do
      expect_privkey =
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"

      path = "m"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0" do
      expect_privkey =
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"

      path = "m/0"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0/2147483647" do
      expect_privkey =
        "xprv9wSp6B7cXJWXZRpDbxkFg3ry2fuSyUfvboJ5Yi6YNw7i1bXmq9QwQ7EwMpeG4cK2pnMqEx1cLYD7cSGSCtruGSXC6ZSVDHugMsZgbuY62m6"

      path = "m/0/2147483647"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0/2147483647/1" do
      expect_privkey =
        "xprv9ysS5br6UbWCRCJcggvpUNMyhVWgD7NypY9gsVTMYmuRtZg8izyYC5Ey4T931WgWbfJwRDwfVFqV3b29gqHDbuEpGcbzf16pdomk54NXkSm"

      path = "m/0/2147483647/1"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0/2147483647/1/2147483646" do
      expect_privkey =
        "xprvA2LfeWWwRCxh4iqigcDMnUf2E3nVUFkntc93nmUYBtb9rpSPYWa8MY3x9ZHSLZkg4G84UefrDruVK3FhMLSJsGtBx883iddHNuH1LNpRrEp"

      path = "m/0/2147483647/1/2147483646"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end

    test "Chain m/0/2147483647/1/2147483646/2" do
      expect_privkey =
        "xprvA48ALo8BDjcRET68R5RsPzF3H7WeyYYtHcyUeLRGBPHXu6CJSGjwW7dWoeUWTEzT7LG3qk6Eg6x2ZoqD8gtyEFZecpAyvchksfLyg3Zbqam"

      path = "m/0/2147483647/1/2147483646/2"

      privkey = derive_key_from_keystring(@master_priv, path)

      assert privkey === expect_privkey
    end
  end

  describe "Public key derivation vector 1" do
    @master_pub "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

    test "Chain M" do
      expect_pubkey =
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

      path = "M"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0" do
      expect_pubkey =
        "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1"

      path = "M/0"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0/1" do
      expect_pubkey =
        "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr"

      path = "M/0/1"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0/1/2" do
      expect_pubkey =
        "xpub6BqyndF6rhZqmgktFCBcapkwubGxPqoAZtQaYewJHXVKZcLdnqBVC8N6f6FSHWUghjuTLeubWyQWfJdk2G3tGgvgj3qngo4vLTnnSjAZckv"

      path = "M/0/1/2"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0/1/2/2" do
      expect_pubkey =
        "xpub6FHUhLbYYkgFQiFrDiXRfQFXBB2msCxKTsNyAExi6keFxQ8sHfwpogY3p3s1ePSpUqLNYks5T6a3JqpCGszt4kxbyq7tUoFP5c8KWyiDtPp"

      path = "M/0/1/2/2"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0/1/2/2/1000000000" do
      expect_pubkey =
        "xpub6GX3zWVgSgPc5tgjE6ogT9nfwSADD3tdsxpzd7jJoJMqSY12Be6VQEFwDCp6wAQoZsH2iq5nNocHEaVDxBcobPrkZCjYW3QUmoDYzMFBDu9"

      path = "M/0/1/2/2/1000000000"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end
  end

  describe "Public key derivation vector 2" do
    @master_pub "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

    test "Chain M" do
      expect_pubkey =
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

      path = "M"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0" do
      expect_pubkey =
        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

      path = "M/0"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0/2147483647" do
      expect_pubkey =
        "xpub6ASAVgeWMg4pmutghzHG3BohahjwNwPmy2DgM6W9wGegtPrvNgjBwuZRD7hSDFhYfunq8vDgwG4ah1gVzZysgp3UsKz7VNjCnSUJJ5T4fdD"

      path = "M/0/2147483647"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0/2147483647/1" do
      expect_pubkey =
        "xpub6CrnV7NzJy4VdgP5niTpqWJiFXMAca6qBm5Hfsry77SQmN1HGYHnjsZSujoHzdxf7ZNK5UVrmDXFPiEW2ecwHGWMFGUxPC9ARipss9rXd4b"

      path = "M/0/2147483647/1"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0/2147483647/1/2147483646" do
      expect_pubkey =
        "xpub6FL2423qFaWzHCvBndkN9cbkn5cysiUeFq4eb9t9kE88jcmY63tNuLNRzpHPdAM4dUpLhZ7aUm2cJ5zF7KYonf4jAPfRqTMTRBNkQL3Tfta"

      path = "M/0/2147483647/1/2147483646"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end

    test "Chain M/0/2147483647/1/2147483646/2" do
      expect_pubkey =
        "xpub6H7WkJf547AiSwAbX6xsm8Bmq9M9P1Gjequ5SipsjipWmtXSyp4C3uwzewedGEgAMsDy4jEvNTWtxLyqqHY9C12gaBmgUdk2CGmwachwnWK"

      path = "M/0/2147483647/1/2147483646/2"

      pubkey = derive_key_from_keystring(@master_pub, path)

      assert pubkey === expect_pubkey
    end
  end

  defp check_key_properties(keystring, xpub?, hardened?, network) do
    key = ExtendedKey.from_string(keystring)
    assert ExtendedKey.public?(key) == xpub?
    assert ExtendedKey.private?(key) == !xpub?
    assert ExtendedKey.hardened?(key) == hardened?
    assert ExtendedKey.normal?(key) == !hardened?
    assert ExtendedKey.network(key) == network
  end

  defp derive_key_from_keystring(keystring, path) when is_binary(path) do
    keystring
    |> ExtendedKey.from_string()
    |> ExtendedKey.derive_chain(path)
    |> ExtendedKey.to_string()
  end

  defp derive_key_pair_from_seed(seed, network, path) when is_binary(path) do
    key = seed |> ExtendedKey.master(network) |> ExtendedKey.derive_chain(path)

    case Keypath.to_list(path) do
      {:xprv, _} ->
        privkey = ExtendedKey.to_string(key)
        pubkey = key |> ExtendedKey.neuter() |> ExtendedKey.to_string()
        {privkey, pubkey}

      {:xpub, _} ->
        {nil, ExtendedKey.to_string(key)}
    end
  end
end
