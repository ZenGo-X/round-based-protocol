use round_based::ProtocolMessage;

#[derive(ProtocolMessage)]
enum Msg<G> {
    VariantA(u16),
    VariantB(String),
    VariantC((u16, String)),
    VariantD(MyStruct<G>),
}
#[derive(ProtocolMessage)]
#[protocol_message(root = round_based)]
enum Msg2<G> {
    VariantA(u16),
    VariantB(String),
    VariantC((u16, String)),
    VariantD(MyStruct<G>),
}

struct MyStruct<T>(T);

fn main() {}
