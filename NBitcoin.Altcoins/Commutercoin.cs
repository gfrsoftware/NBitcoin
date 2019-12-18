using NBitcoin.DataEncoders;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace NBitcoin.Altcoins
{
	// Reference: https://github.com/CommuterCoin/CommuterCoin/blob/master/src/chainparams.cpp
	public class Commutercoin : NetworkSetBase
	{
		public static Commutercoin Instance { get; } = new Commutercoin();

		public override string CryptoCode => "CMCN";

		private Commutercoin()
		{

		}

		//Format visual studio
		//{({.*?}), (.*?)}
		//Tuple.Create(new byte[]$1, $2)
		static Tuple<byte[], int>[] pnSeed6_main = {
			Tuple.Create(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x12, 0xdb, 0xfa, 0xce}, 12226),
			Tuple.Create(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0d, 0x3a, 0xfa, 0x13}, 12226)
		};
		static Tuple<byte[], int>[] pnSeed6_test = { };

#pragma warning disable CS0618 // Type or member is obsolete
		public class CommutercoinConsensusFactory : ConsensusFactory
		{
			private CommutercoinConsensusFactory()
			{

			}

			public static CommutercoinConsensusFactory Instance { get; } = new CommutercoinConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new CommutercoinBlockHeader();
			}

			public override Block CreateBlock()
			{
				return new CommutercoinBlock(new CommutercoinBlockHeader());
			}
		}

		public class CommutercoinBlockHeader : BlockHeader
		{
			public override uint256 GetPoWHash()
			{
				var headerBytes = this.ToBytes();
				var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
				return new uint256(h);
			}
		}

		public class CommutercoinBlock : Block
		{
			public CommutercoinBlock(CommutercoinBlockHeader header) : base(header)
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return CommutercoinConsensusFactory.Instance;
			}
		}
#pragma warning restore CS0618 // Type or member is obsolete

		/// <summary>
		/// Do we need to offer this string parser helper?
		/// </summary>
		public class CommutercoinMainnetAddressStringParser : NetworkStringParser
		{
			public override bool TryParse(string str, Network network, Type targetType, out IBitcoinString result)
			{
				// Private Key
				if(str.StartsWith("????", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x88;
						decoded[2] = 0xB2;
						decoded[3] = 0xE4;
						result = new BitcoinExtKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{

					}
				}
				// Public Key
				if (str.StartsWith("????", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtPubKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x35;
						decoded[2] = 0x87;
						decoded[3] = 0xCF;
						result = new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{

					}
				}
				// Other
				return base.TryParse(str, network, out result);
			}
		}

		protected override NetworkBuilder CreateMainnet()
		{
			NetworkBuilder builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 0,
				MajorityEnforceBlockUpgrade = 0,
				MajorityRejectBlockOutdated = 0,
				MajorityWindow = 0,
				BIP34Hash = new uint256(),
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(0 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(0 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 0,
				MinerConfirmationWindow = 0,
				CoinbaseMaturity = 0,
				LitecoinWorkCalculation = true,
				ConsensusFactory = CommutercoinConsensusFactory.Instance
			})
				.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 51 })
				.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 50 })
				.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 178 })
				.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
				.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
				.SetNetworkStringParser(new CommutercoinMainnetAddressStringParser()) // TODO: Do we need this?
				.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("cmcn"))
				.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("cmcn"))
				.SetMagic(0x3e8b3ac9)
				.SetPort(12226)
				.SetRPCPort(12225)
				.SetName("cmcn-main")
				.AddAlias("cmcn-mainnet")
				.AddAlias("commutercoin-main")
				.AddAlias("commutercoin-mainnet")
				.AddDNSSeeds(new[]
				{
					new DNSSeedData("18.219.250.206", "18.219.250.206"),
					new DNSSeedData("13.58.250.19", "13.58.250.19")
				})
				.AddSeeds(ToSeed(pnSeed6_main))
				.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000144F520CAB2F042D86EF6A9E4264A0B50291D802A30BA37E2D5C0ADA4FEF045A07CC6C5DFFFF0F1E860D2500010100000007CC6C5D010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF4200012A3E4B65697220537461726D65722073617973204D50732077696C6C2070726F706F7365206C656769736C6174696F6E20746F2073746F70206E6F206465616CFFFFFFFF010000000000000000000000000000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			throw new NotImplementedException();
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			return builder;
		}
	}
}
