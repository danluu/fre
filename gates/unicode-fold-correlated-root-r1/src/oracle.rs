#[derive(Clone, Debug)]
pub enum Atom {
    Fold(Vec<char>),
    Exact(char),
}

impl Atom {
    fn matches(&self, scalar: char) -> bool {
        match self {
            Self::Fold(members) => members.binary_search(&scalar).is_ok(),
            Self::Exact(expected) => *expected == scalar,
        }
    }

    pub fn members(&self) -> &[char] {
        match self {
            Self::Fold(members) => members,
            Self::Exact(scalar) => std::slice::from_ref(scalar),
        }
    }

    pub fn representative(&self, selector: usize) -> char {
        let members = self.members();
        members[selector % members.len()]
    }

    pub fn minimum_utf8_bytes(&self) -> usize {
        self.members()
            .iter()
            .map(|scalar| scalar.len_utf8())
            .min()
            .expect("every atom has at least one scalar")
    }

    pub fn maximum_utf8_bytes(&self) -> usize {
        self.members()
            .iter()
            .map(|scalar| scalar.len_utf8())
            .max()
            .expect("every atom has at least one scalar")
    }
}

#[derive(Clone, Debug)]
pub struct Branch {
    pub atoms: Vec<Atom>,
}

impl Branch {
    pub fn representative_bytes(&self, selector: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (atom_index, atom) in self.atoms.iter().enumerate() {
            let scalar = atom.representative(selector.wrapping_add(atom_index));
            let mut encoded = [0_u8; 4];
            bytes.extend_from_slice(scalar.encode_utf8(&mut encoded).as_bytes());
        }
        bytes
    }

    pub fn minimum_bytes(&self) -> usize {
        self.atoms.iter().map(Atom::minimum_utf8_bytes).sum()
    }

    pub fn maximum_bytes(&self) -> usize {
        self.atoms.iter().map(Atom::maximum_utf8_bytes).sum()
    }
}

#[derive(Debug)]
pub struct Oracle {
    branches: Vec<Branch>,
}

impl Oracle {
    pub fn new(branches: &[Branch]) -> Self {
        Self {
            branches: branches.to_vec(),
        }
    }

    pub fn find(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        self.find_window(haystack, 0, haystack.len())
    }

    pub fn find_at(&self, haystack: &[u8], start: usize) -> Option<(usize, usize)> {
        self.find_window(haystack, start, haystack.len())
    }

    pub fn find_window(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<(usize, usize)> {
        assert!(start <= end && end <= haystack.len());
        for candidate in start..end {
            for branch in &self.branches {
                if let Some(match_end) = match_branch(branch, haystack, candidate, end) {
                    return Some((candidate, match_end));
                }
            }
        }
        None
    }

    pub fn is_match(&self, haystack: &[u8]) -> bool {
        self.find(haystack).is_some()
    }

    pub fn matches(&self, haystack: &[u8]) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let mut cursor = 0_usize;
        while cursor < haystack.len() {
            let Some(span) = self.find_at(haystack, cursor) else {
                break;
            };
            assert!(span.1 > span.0, "the frozen literal recipes are non-empty");
            spans.push(span);
            cursor = span.1;
        }
        spans
    }
}

fn match_branch(
    branch: &Branch,
    haystack: &[u8],
    start: usize,
    window_end: usize,
) -> Option<usize> {
    let mut cursor = start;
    for atom in &branch.atoms {
        let (scalar, width) = decode_one(haystack, cursor, window_end)?;
        if !atom.matches(scalar) {
            return None;
        }
        cursor = cursor.checked_add(width)?;
    }
    Some(cursor)
}

fn decode_one(haystack: &[u8], cursor: usize, end: usize) -> Option<(char, usize)> {
    let lead = *haystack.get(cursor)?;
    let width = match lead {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let scalar_end = cursor.checked_add(width)?;
    if scalar_end > end {
        return None;
    }
    let text = std::str::from_utf8(&haystack[cursor..scalar_end]).ok()?;
    let mut scalars = text.chars();
    let scalar = scalars.next()?;
    if scalars.next().is_some() {
        return None;
    }
    Some((scalar, width))
}
