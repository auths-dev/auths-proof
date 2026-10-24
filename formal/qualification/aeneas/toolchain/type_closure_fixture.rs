//! Source declarations for the ADT closure stage. Final assertions must retain
//! fields, variant identities, recursive edges, bounds and pointer metadata.
pub struct Node<'a, T: Copy> {
    pub value: &'a T,
    pub next: Option<Box<Node<'a, T>>>,
}

pub enum Choice<'a, T: Copy> {
    Empty,
    Borrowed(&'a T),
    Recursive(Box<Node<'a, T>>),
}

pub struct ArrayRow<'a, const N: usize> {
    pub values: &'a [u8; N],
}

pub trait Family {
    type Item;
}

pub struct FamilyRow<'a, F: Family>
where
    F::Item: 'a,
{
    pub value: &'a F::Item,
}

pub struct Words;
impl Family for Words {
    type Item = u64;
}

pub fn first(node: &Node<'_, u64>) -> u64 {
    *node.value
}

pub fn family_value(row: &FamilyRow<'_, Words>) -> u64 {
    *row.value
}

pub trait StaticFamily {
    type Item: 'static;
}

pub struct Marker<const N: usize>;

impl<const N: usize> StaticFamily for Marker<N> {
    type Item = [u8; N];
}

pub struct NestedMarker(Marker<32>);

impl StaticFamily for NestedMarker {
    type Item = (Marker<32>, [u8; 32]);
}

pub fn static_family(value: <NestedMarker as StaticFamily>::Item) -> usize {
    value.1.len()
}
