## Avail Contracts
This repository contains all Avail contracts related to the arbitrary message bridge between Avail and Ethereum.

## Documentation
You can find additional documentation in the form of NatSpec and line-by-line comments.

## Usage
### Build
```bash
forge build
```

### Test
```bash
forge test -vvv
```
To use the `intense` profile:
```bash
FOUNDRY_PROFILE=intense forge test -vvv
```

### Coverage
```bash
forge coverage
```

### Format
```bash
forge fmt
```

### Gas Snapshots
```bash
forge snapshot
```

### Deploy
Deployments require a proxy admin address and a `Vectorx` deployment on the chain you're deploying.
```bash
ADMIN=<admin_address> forge script script/Deploy.s.sol --rpc-url <your_rpc_url> --private-key <your_private_key>
```
