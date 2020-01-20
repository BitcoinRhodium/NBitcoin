using NBitcoin.Altcoins.HashX11;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace NBitcoin.Altcoins
{

	/// <summary>
	/// CoinType is BIP 44 Code. SIP 0044 describes registered coin type.
	/// </summary>
	public enum CoinType
	{
		BRhodium = 10291,
		BRhodiumTestNet = 1,
		BRhodiumRegNet = 1
	}

	/// <summary>
	/// <see cref="https://www.bitcoinrh.org">Bitcoin Rhodium</see> Altcoin definition
	/// </summary>
	public class BRhodium : NetworkSetBase
	{
		public static BRhodium Instance { get; } = new BRhodium();

		public override string CryptoCode => "XRC";

		private BRhodium()
		{
		}

#pragma warning disable CS0618 // Type or member is obsolete
		public class BRhodiumConsensusFactory : ConsensusFactory
		{
			public static BRhodiumConsensusFactory Instance { get; } = new BRhodiumConsensusFactory();

			public new BRhodiumBlockHeader CreateBlockHeader()
			{
				return new BRhodiumBlockHeader();
			}

			public new BRhodiumBlock CreateBlock()
			{
				return new BRhodiumBlock(new BRhodiumBlockHeader());
			}

			protected bool IsHeadersPayload(Type type)
			{
				var baseType = typeof(HeadersPayload).GetTypeInfo();
				return baseType.IsAssignableFrom(type.GetTypeInfo());
			}
		}


		/// <summary>
		/// A block header, this will create a work hash based on the X13 hash algos.
		/// </summary>
		public class BRhodiumBlockHeader : BlockHeader
		{
			const int CurrentVersion = 45;

			private readonly BRhodiumX13 x13;

			public BRhodiumBlockHeader() : base()
			{
				x13 = BRhodiumX13.Instance;
			}

			/// <summary>
			/// Calculates the hash of the header. Only used for the header hash.
			/// </summary>
			/// <param name="data"></param>
			/// <param name="offset"></param>
			/// <param name="count"></param>
			/// <returns></returns>
			private byte[] CalculateHash(byte[] data, int offset, int count)
			{
				byte[] hashData = data.SafeSubarray(offset, count);
				uint256 hash = null;
				hash = Hashes.Hash256(hashData);
				return hash.ToBytes();
			}

			protected override HashStreamBase CreateHashStream()
			{
				return BufferedHashStream.CreateFrom(CalculateHash);
			}

			public uint256 GetPoWHash(int height, int forkHeight)
			{
				var hashVersion = height > forkHeight ? 2 : 1;
				return new uint256(x13.Hash(this.ToBytes(), hashVersion));
			}
		}

		public class BRhodiumBlock : Block
		{
			public BRhodiumBlock(BRhodiumBlockHeader blockHeader) : base(blockHeader)
			{
			}

			public override ConsensusFactory GetConsensusFactory()
			{
				return BRhodiumConsensusFactory.Instance;
			}
		}

		public class BRhodiumConsensus : Consensus
		{
			public Target PowLimit2;
			public int PowLimit2Height;
			public Dictionary<int, uint256> Checkpoints = new Dictionary<int, uint256>();

		}

		protected override NetworkBuilder CreateMainnet()
		{
			NetworkBuilder builder = new NetworkBuilder();
			var magic = BitConverter.ToUInt32(new byte[] { 0x33, 0x33, 0x34, 0x35 }, 0);
			var consensus = new BRhodiumConsensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"),
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowLimit2 = new Target(new uint256("0000000000092489000000000000000000000000000000000000000000000000")),
				PowLimit2Height = 1648,
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				CoinType = (int)CoinType.BRhodium,
				CoinbaseMaturity = 50,
				ConsensusFactory = BRhodiumConsensusFactory.Instance
			};

			consensus.Checkpoints.Add(17, new uint256("2430c4151e10cdc5ccbdea56b909c7c37ab2a852d3e7fb908e0a32493e2ac706"));
			consensus.Checkpoints.Add(117, new uint256("bf3082be3b2da88187ebeb902548b41dbff3bcac6687352e0c47d902acd28e62"));
			consensus.Checkpoints.Add(400, new uint256("20cb04127f12c1ae7a04ee6dc4c7e36f4c85ee2038c92126b3fd537110d96595"));
			consensus.Checkpoints.Add(800, new uint256("df37ca401ecccfc6dedf68ab76a7161496ad93d47c2a474075efb3220e3f3526"));
			consensus.Checkpoints.Add(26800, new uint256("c4efd4b6fa294fd72ab6f614dd6705eea43d0a83cd03d597c3214eaaf857a4b6"));

			builder.SetConsensus(consensus)
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 61 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 123 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { (100) })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("rh"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("rh"))
			.SetMagic(magic)
			.SetPort(37270)
			.SetRPCPort(19660)
			.SetName("xrc-main")
			.AddAlias("xrc-mainnet")
			.AddAlias("brhodium-main")
			.AddAlias("brhodium-mainnet")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("dns.btrmine.com", "dns.btrmine.com"),
				new DNSSeedData("dns2.btrmine.com", "dns2.btrmine.com"),
				new DNSSeedData("xrc.dnsseed.ekcdd.com", "xrc.dnsseed.ekcdd.com")
			})
			.SetGenesis("2d0000000000000000000000000000000000000000000000000000000000000000000000493c4e38eae08f8a348ceebc40864dab1411baafbd3416c6219c366781aabd86c0f21f5affff0f1e000000000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2204ffff0f1e01041a52656c6561736520746865204b72616b656e212121205a657573ffffffff0100000000000000002204ffff0f1e01041a52656c6561736520746865204b72616b656e212121205a65757300000000");



			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			NetworkBuilder builder = new NetworkBuilder();
			var magic = BitConverter.ToUInt32(new byte[] { 0x71, 0x31, 0x21, 0x11 }, 0); //0x5223570;
			builder = new NetworkBuilder();
			builder.SetConsensus(new BRhodiumConsensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				PowLimit = new Target(uint256.Parse("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowLimit2 = new Target(uint256.Parse("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")), // Testnet the same
				PowLimit2Height = 0,
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				CoinType = (int)CoinType.BRhodiumTestNet,
				CoinbaseMaturity = 100,
				ConsensusFactory = BRhodiumConsensusFactory.Instance
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 65 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 128 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 65 + 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("th"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("th"))
			.SetMagic(magic)
			.SetPort(16665)
			.SetRPCPort(16661)
			.SetName("xrc-test")
			.AddAlias("xrc-testnet")
			.AddAlias("brhodium-test")
			.AddAlias("brhodium-testnet")

			.AddDNSSeeds(new[]
			{
					new DNSSeedData("testnet1.Rhodiumplatform.com", "testnet1.Rhodiumplatform.com"),
					new DNSSeedData("testnet2.Rhodiumplatform.com", "testnet2.Rhodiumplatform.com"),
					new DNSSeedData("testnet3.Rhodiumplatform.com", "testnet3.Rhodiumplatform.com"),
					new DNSSeedData("testnet4.Rhodiumplatform.com", "testnet4.Rhodiumplatform.com")
			})
			.SetGenesis("2d0000000000000000000000000000000000000000000000000000000000000000000000493c4e38eae08f8a348ceebc40864dab1411baafbd3416c6219c366781aabd86808c105bffff0f1e000000000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2204ffff0f1e01041a52656c6561736520746865204b72616b656e212121205a657573ffffffff0100000000000000002204ffff0f1e01041a52656c6561736520746865204b72616b656e212121205a65757300000000");

			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			NetworkBuilder builder = new NetworkBuilder();
			var magic = BitConverter.ToUInt32(new byte[] { 0xcd, 0xf2, 0xc0, 0xef }, 0);
			builder = new NetworkBuilder();
			builder.SetConsensus(new BRhodiumConsensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				PowLimit = new Target(uint256.Parse("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowLimit2 = new Target(uint256.Parse("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowLimit2Height = 0,
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = true,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				CoinType = (int)CoinType.BRhodiumRegNet,
				CoinbaseMaturity = 100,
				ConsensusFactory = BRhodiumConsensusFactory.Instance
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 65 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 128 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 65 + 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("rrh"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("rrh"))
			.SetMagic(magic)
			.SetPort(16666)
			.SetRPCPort(16662)
			.SetName("xrc-reg")
			.AddAlias("xrc-regtest")
			.AddAlias("brhodium-reg")
			.AddAlias("brhodium-regtest")
			.SetGenesis("2d0000000000000000000000000000000000000000000000000000000000000000000000b7052990099cd0bc8b7fd5c60d12696ce2020b7fe0834406f677ae437a3249fd808c105bffff7f20000000000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2204ffff7f2001041a52656c6561736520746865204b72616b656e212121205a657573ffffffff010000000000000000232103d1b6cd5f956ccedf5877c89843a438bfb800468133fb2e73946e1452461a9b1aac00000000");

			return builder;
		}
	}
}
