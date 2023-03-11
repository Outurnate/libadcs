use derive_utils::quick_derive;
use proc_macro::TokenStream;

#[proc_macro_derive(Values)]
pub fn derive_iterator(input: TokenStream) -> TokenStream
{
  quick_derive!
  {
    input,
    bcder::encode::Values,
    trait Values
    {
      fn encoded_len(&self, mode: bcder::Mode) -> usize;
      fn write_encoded<W: std::io::Write>(&self, mode: bcder::Mode, target: &mut W) -> Result<(), std::io::Error>;
    }
  }
}