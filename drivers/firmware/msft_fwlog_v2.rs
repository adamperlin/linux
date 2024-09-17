// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;

module! {
    type: FwLog,
    name: "msft_fwlog_v2",
    author: "Adam Perlin <adamperlin@microsoft.com>; Hayden Rinn <haydenrinn@microsoft.com>",
    description: "MSFT Firmware Log driver v2",
    license: "GPL",
}

struct FwLog {}

impl kernel::Module for RustMinimal {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Hello world\n");

        Ok(Self)
    }
}
