/**
 * A tiny in-memory stand-in for the mongoose Model surface the core uses,
 * so the package tests need no Mongo. Documents are plain objects; `new
 * Model(doc)` returns one with save()/isNew like a mongoose document.
 */
let seq = 1;

function matches(doc, filter) {
    return Object.entries(filter).every(([k, v]) => String(doc[k]) === String(v));
}

function chain(value) {
    const c = { lean: async () => value, select: () => c, then: (ok, ko) => Promise.resolve(value).then(ok, ko) };
    return c;
}

function memModel() {
    const rows = [];
    function Model(doc) {
        const self = { ...doc, _id: doc._id || `oid${seq++}`, isNew: true };
        self.save = async () => {
            const copy = { ...self };
            delete copy.save; delete copy.isNew;
            const i = rows.findIndex(r => r._id === self._id);
            if (i >= 0) rows[i] = copy; else rows.push(copy);
            self.isNew = false;
            return self;
        };
        return self;
    }
    Model.rows = rows;
    Model.create = async doc => {
        const d = new Model(doc);
        await d.save();
        return { ...d, toObject: () => ({ ...d }) };
    };
    Model.findOne = filter => {
        const found = rows.find(r => matches(r, filter));
        if (!found) return chain(null);
        // return something save()-able (for connections)
        const d = new Model(found);
        d.isNew = false;
        return chain(d);
    };
    Model.findById = id => chain(rows.find(r => String(r._id) === String(id)) || null);
    Model.findOneAndDelete = filter => {
        const i = rows.findIndex(r => matches(r, filter));
        if (i < 0) return chain(null);
        const [doc] = rows.splice(i, 1);
        return chain(doc);
    };
    Model.updateOne = async (filter, update) => {
        const doc = rows.find(r => matches(r, filter));
        if (doc && update.$set) Object.assign(doc, update.$set);
        return { matchedCount: doc ? 1 : 0 };
    };
    Model.find = () => chain([...rows]);
    return Model;
}

module.exports = { memModel };
