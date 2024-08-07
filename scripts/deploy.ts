import hre, {ethers, upgrades} from "hardhat";

async function verifyContract(
    address: string,
    constructorArguments: any
) {
    try {
        await hre.run("verify:verify", {
            address: address,
            constructorArguments: constructorArguments
        });
    } catch {
        console.log("Failed to verify", address);
    }
}

async function main() {
    const SwapRouter02 = '0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E';
    const quoterV2 = '0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3';

    // Get the admin address
    const [deployer] = await ethers.getSigners();
    const adminAddress = deployer.address; // You can replace this with a specific address if needed

    console.log(`Admin address: ${adminAddress}`);

    const SimpleEigenContract = await ethers.getContractFactory("SimpleEigenContract");
    const contract = await upgrades.deployProxy(SimpleEigenContract, [adminAddress], {
        initializer: "initialize",
    });
    await contract.waitForDeployment();
    console.log("SimpleEigenContract deployed to:", await contract.getAddress());
    const DAO_ROLE = await contract.DAO_ROLE();
    await contract.grantRole(DAO_ROLE, deployer.address);
    await verifyContract(await contract.getAddress(), []);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
