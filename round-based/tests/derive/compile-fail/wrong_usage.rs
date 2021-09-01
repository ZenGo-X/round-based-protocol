use round_based::ProtocolMessage;

#[derive(ProtocolMessage)]
enum Msg {
    // Unnamed variant with single field is the only correct enum variant
    // that doesn't contradicts with ProtocolMessage derivation
    VariantA(u16),
    // Error: You can't have named variants
    VariantB { n: u32 },
    // Error: Variant must have exactly 1 field
    VariantC(u32, String),
    // Error: Variant must have exactly 1 field!!
    VariantD(),
    // Error: Union variants are not permitted
    VariantE,
}

// Structure cannot implement ProtocolMessage
#[derive(ProtocolMessage)]
struct Msg2 {
    some_field: u64,
}

// Union cannot implement ProtocolMessage
#[derive(ProtocolMessage)]
union Msg3 {
    variant: u64,
}

fn main() {}
