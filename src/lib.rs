pub mod archive;
pub mod cli;
pub mod decode_rf;
pub mod decompile;
pub mod decompose;
pub mod error;
pub mod ext4;
pub mod fbpk;
pub mod globals;
pub mod gzip;
pub mod hwcfg;
pub mod manifest;
pub mod pipeline;
pub mod recover_source;
pub mod source_tree;
pub mod symbolicate;
pub mod toc;
pub mod tokens;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(2 + 2, 4);
    }
}
